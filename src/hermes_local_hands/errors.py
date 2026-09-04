"""Domain errors.  Callers should treat all failures as deny decisions."""


class LocalHandsError(Exception):
    """Base class for an expected, safe failure."""


class PolicyError(LocalHandsError):
    pass


class AuthenticationError(LocalHandsError):
    pass


class NotFoundError(LocalHandsError):
    pass


class ConflictError(LocalHandsError):
    pass


class UnsafePathError(PolicyError):
    pass


class ExecutionError(LocalHandsError):
    pass


class UncertainExecutionError(ExecutionError):
    """Execution began, but its complete outcome cannot be proven."""
