"""
Dependencias de autenticacao usadas pelos endpoints protegidos.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.auth.security import decode_access_token
from src.db.repository import get_user_by_id


bearer_scheme = HTTPBearer(auto_error=False)


def _auth_error(
    message: str,
    status_code: int = status.HTTP_401_UNAUTHORIZED,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={
            "status": "error",
            "error_code": "auth_error",
            "message": message,
            "details": {},
        },
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict[str, Any]:
    """
    Retorna o usuario autenticado a partir do token Bearer.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _auth_error("Token de acesso ausente.")

    try:
        payload = decode_access_token(credentials.credentials)
        user_id = int(payload.get("sub"))
    except Exception as exc:
        raise _auth_error("Token de acesso invalido ou expirado.") from exc

    try:
        user = get_user_by_id(user_id)
    except Exception as exc:
        raise _auth_error(
            "Nao foi possivel consultar o usuario autenticado.",
            status.HTTP_503_SERVICE_UNAVAILABLE,
        ) from exc

    if user is None:
        raise _auth_error("Usuario autenticado nao encontrado.")
    if not bool(user.get("is_active")):
        raise _auth_error("Usuario autenticado esta inativo.", status.HTTP_403_FORBIDDEN)
    return user


def require_admin(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Exige usuario com papel admin.
    """
    if current_user.get("role") != "admin":
        raise _auth_error(
            "Apenas administradores podem executar esta acao.",
            status.HTTP_403_FORBIDDEN,
        )
    return current_user

