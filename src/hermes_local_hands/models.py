"""Small, serialisable domain objects for the local-only service."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class RequestKind(StrEnum):
    PATCH = "patch"
    TEST = "test"


class RequestState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class WorkspacePolicy:
    workspace_id: str
    root: str
    read_allowlist: tuple[str, ...]
    test_profiles: dict[str, tuple[str, ...]] = field(default_factory=dict)
    max_read_bytes: int = 262_144
    write_allowlist: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["read_allowlist"] = list(self.read_allowlist)
        data["write_allowlist"] = list(self.write_allowlist)
        data["test_profiles"] = {name: list(argv) for name, argv in self.test_profiles.items()}
        return data


@dataclass(frozen=True)
class PendingRequest:
    request_id: str
    kind: RequestKind
    workspace_id: str
    payload: dict[str, Any]
    idempotency_key: str
    base_head: str
    policy_hash: str
    state: RequestState
    created_at: str
    client_id: str = ""
    expires_at: str = ""
    result: dict[str, Any] | None = None


@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    sequence: int
    occurred_at: str
    event: str
    payload: dict[str, Any]
    previous_hash: str
    receipt_hash: str
    signature: str
    schema: int = 1
