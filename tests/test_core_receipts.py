from __future__ import annotations

from hermes_local_hands.receipts import ReceiptLedger, ReceiptSigner
from hermes_local_hands.storage import Store


def test_receipts_are_canonical_hash_chained_and_signed(tmp_path):
    ledger = ReceiptLedger(Store(str(tmp_path / "state.sqlite")), ReceiptSigner(b"x" * 32))
    first = ledger.append("one", {"b": 2, "a": 1}, "2026-01-01T00:00:00+00:00")
    second = ledger.append("two", {"ok": True}, "2026-01-01T00:00:01+00:00")
    assert first.previous_hash == "0" * 64
    assert second.previous_hash == first.receipt_hash
    assert len(first.receipt_hash) == 64
    assert first.signature != second.signature
    assert ledger.verify()
    ledger.store.connection.execute("UPDATE receipts SET event='tampered' WHERE sequence=1")
    assert not ledger.verify()
