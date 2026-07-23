from __future__ import annotations


class TraceFenceError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: str = "TRACEFENCE_ERROR",
        status_code: int = 400,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


class AuthenticationError(TraceFenceError):
    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message, code="AUTHENTICATION_FAILED", status_code=401)


class AuthorizationError(TraceFenceError):
    def __init__(self, message: str = "Operation is not authorized") -> None:
        super().__init__(message, code="AUTHORIZATION_FAILED", status_code=403)


class NotFoundError(TraceFenceError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="NOT_FOUND", status_code=404)


class ConflictError(TraceFenceError):
    def __init__(self, message: str, *, code: str = "CONFLICT") -> None:
        super().__init__(message, code=code, status_code=409)
