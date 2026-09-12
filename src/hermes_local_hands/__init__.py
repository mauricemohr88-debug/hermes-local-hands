"""Hermes Local Hands - local approval boundary for remote agent work."""

from importlib import import_module
from typing import Any

from .models import PendingRequest, RequestKind, RequestState, WorkspacePolicy

__all__ = [
    "LocalHandsService",
    "PendingRequest",
    "ReceiptLedger",
    "ReceiptSigner",
    "RequestKind",
    "RequestState",
    "Store",
    "WorkspacePolicy",
]


def __getattr__(name: str) -> Any:
    # Help and diagnostics must remain available before Git or the service is ready.
    modules = {
        "LocalHandsService": "service",
        "ReceiptLedger": "receipts",
        "ReceiptSigner": "receipts",
        "Store": "storage",
    }
    if name not in modules:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(f".{modules[name]}", __name__), name)
    globals()[name] = value
    return value
