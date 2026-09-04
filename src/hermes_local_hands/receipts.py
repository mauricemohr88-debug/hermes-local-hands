"""Domain-separated, hash-chained receipts signed by a pinned Ed25519 key."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import ConflictError
from .models import Receipt
from .storage import Store, canonical_json

RECEIPT_SCHEMA = 1
_RECEIPT_DOMAIN = b"hermes-local-hands.receipt.v1\x00"
_GENESIS_HASH = "0" * 64


def _receipt_message(body: dict[str, Any]) -> bytes:
    return _RECEIPT_DOMAIN + canonical_json(body).encode("utf-8")


class ReceiptSigner:
    def __init__(self, seed: bytes | None = None) -> None:
        self._key = (
            Ed25519PrivateKey.from_private_bytes(seed)
            if seed is not None
            else Ed25519PrivateKey.generate()
        )

    @classmethod
    def load_or_create(cls, key_path: str, *, store: Store | None = None) -> ReceiptSigner:
        """Load a protected signing key, creating it only for an unbound empty store.

        Supplying ``store`` is the safe persistent-service API: a missing key fails closed once
        the database has a pinned identity or any receipts, and an existing/replaced key is
        checked against the pinned public-key fingerprint before it is returned.
        """

        path = Path(key_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, os.O_RDONLY | nofollow)
        except FileNotFoundError:
            if store is not None and (
                store.receipt_count() > 0 or store.receipt_signing_key_fingerprint() is not None
            ):
                raise RuntimeError(
                    "receipt signing key is missing for an initialized ledger"
                ) from None
            signer = cls()
            raw = signer._private_seed()
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                # Another process won creation. Load and validate its completed key instead of
                # ever overwriting it.
                return cls.load_or_create(str(path), store=store)
            try:
                written = 0
                while written < len(raw):
                    count = os.write(descriptor, raw[written:])
                    if count < 1:  # pragma: no cover - defensive OS failure
                        raise OSError("receipt key write made no progress")
                    written += count
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if store is not None:
                store.pin_receipt_signing_key(signer.public_key_fingerprint)
            return signer

        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise PermissionError("receipt signing key must be a regular file")
            if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
                raise PermissionError("receipt signing key must have mode 0600")
            raw = os.read(descriptor, 33)
        finally:
            os.close(descriptor)
        if len(raw) != 32:
            raise ValueError("invalid receipt signing key")
        signer = cls(raw)
        if store is not None:
            if (
                store.receipt_signing_key_fingerprint() is None
                and store.receipt_count() > 0
                and not _verify_receipts(store, signer, require_pinned_key=False)
            ):
                raise ConflictError(
                    "receipt signing key cannot verify the existing unpinned ledger"
                )
            store.pin_receipt_signing_key(signer.public_key_fingerprint)
        return signer

    def _private_seed(self) -> bytes:
        return self._key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    @property
    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_bytes).decode("ascii")

    @property
    def public_key_fingerprint(self) -> str:
        return hashlib.sha256(self.public_key_bytes).hexdigest()

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self._key.sign(message)).decode("ascii")

    @staticmethod
    def verify(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
        try:
            public_key = base64.b64decode(public_key_b64, validate=True)
            signature = base64.b64decode(signature_b64, validate=True)
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except (binascii.Error, ValueError, InvalidSignature):
            return False


def _verify_receipts(store: Store, signer: ReceiptSigner, *, require_pinned_key: bool) -> bool:
    if (
        require_pinned_key
        and store.receipt_signing_key_fingerprint() != signer.public_key_fingerprint
    ):
        return False
    previous = _GENESIS_HASH
    for row in store.receipts():
        schema = int(row["schema"])
        body = {
            "domain": "hermes-local-hands.receipt",
            "schema": schema,
            "receipt_id": str(row["receipt_id"]),
            "occurred_at": str(row["occurred_at"]),
            "event": str(row["event"]),
            "payload": json.loads(str(row["payload_json"])),
            "previous_hash": previous,
        }
        message = _receipt_message(body)
        digest = hashlib.sha256(message).hexdigest()
        if (
            schema != RECEIPT_SCHEMA
            or str(row["previous_hash"]) != previous
            or str(row["receipt_hash"]) != digest
            or not ReceiptSigner.verify(signer.public_key_b64, message, str(row["signature"]))
        ):
            return False
        previous = digest
    return True


class ReceiptLedger:
    def __init__(
        self, store: Store, signer: ReceiptSigner, *, verify_existing: bool = True
    ) -> None:
        self.store, self.signer = store, signer
        if (
            self.store.receipt_signing_key_fingerprint() is None
            and self.store.receipt_count() > 0
            and not _verify_receipts(self.store, signer, require_pinned_key=False)
        ):
            raise ConflictError("signing key cannot verify the existing unpinned ledger")
        self.store.pin_receipt_signing_key(signer.public_key_fingerprint)
        self.store.assert_integrity()
        if verify_existing and self.store.receipt_count() and not self.verify():
            raise ConflictError("existing receipt ledger failed cryptographic verification")

    @classmethod
    def open(cls, store: Store, key_path: str | None = None) -> ReceiptLedger:
        """Open a persistent ledger with a fail-closed store-bound signing key."""

        resolved = key_path or str(Path(store.path).parent / "receipt-signing-key.ed25519")
        signer = ReceiptSigner.load_or_create(resolved, store=store)
        return cls(store, signer)

    def append(
        self, event: str, payload: dict[str, Any], occurred_at: str | None = None
    ) -> Receipt:
        if not event:
            raise ValueError("receipt event is required")
        occurred_at = occurred_at or datetime.now(UTC).isoformat()
        receipt_id = secrets.token_urlsafe(16)
        with self.store.transaction():
            previous = self.store.last_receipt_hash()
            body = {
                "domain": "hermes-local-hands.receipt",
                "schema": RECEIPT_SCHEMA,
                "receipt_id": receipt_id,
                "occurred_at": occurred_at,
                "event": event,
                "payload": payload,
                "previous_hash": previous,
            }
            message = _receipt_message(body)
            digest = hashlib.sha256(message).hexdigest()
            signature = self.signer.sign(message)
            sequence = self.store.append_receipt(
                (
                    RECEIPT_SCHEMA,
                    receipt_id,
                    occurred_at,
                    event,
                    canonical_json(payload),
                    previous,
                    digest,
                    signature,
                )
            )
        return Receipt(
            receipt_id=receipt_id,
            sequence=sequence,
            occurred_at=occurred_at,
            event=event,
            payload=payload,
            previous_hash=previous,
            receipt_hash=digest,
            signature=signature,
            schema=RECEIPT_SCHEMA,
        )

    def verify(self) -> bool:
        return _verify_receipts(self.store, self.signer, require_pinned_key=True)
