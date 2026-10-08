
import os
import secrets

from fastapi import (
    Header,
    HTTPException,
    status,
)


def require_admin(
    x_admin_key: str | None = Header(
        default=None,
    ),
):
    """
    Require an administrator API key.

    Set ADMIN_API_KEY as an environment variable
    before running the server.
    """

    expected_key = os.getenv(
        "ADMIN_API_KEY"
    )

    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail=(
                "Administrator authentication "
                "is not configured."
            ),
        )

    if (
        x_admin_key is None
        or not secrets.compare_digest(
            x_admin_key,
            expected_key,
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid administrator API key",
        )

    return "ADMIN"
