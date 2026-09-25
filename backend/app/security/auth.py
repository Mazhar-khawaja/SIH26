from fastapi import Security, HTTPException, status, Request
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
import jwt
from typing import Optional, List

from app.config.settings import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
security = HTTPBearer(auto_error=False)

class Role:
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

def verify_api_key(api_key: str = Security(api_key_header)) -> bool:
    if api_key and api_key == settings.api_key:
        return True
    return False

def verify_jwt(credentials: HTTPAuthorizationCredentials = Security(security)) -> Optional[dict]:
    if not credentials:
        return None
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm]
        )
        return payload
    except jwt.PyJWTError:
        return None

def get_current_user(
    api_key: str = Security(api_key_header),
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> dict:
    # 1. Check API Key for machine-to-machine
    if verify_api_key(api_key):
        return {"role": Role.ADMIN, "type": "api_key"}

    # 2. Check JWT for users
    payload = verify_jwt(credentials)
    if payload:
        return {"role": payload.get("role", Role.VIEWER), "type": "jwt", "user": payload.get("sub")}

    # 3. Deny if neither
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: dict = Security(get_current_user)):
        if user["role"] not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted"
            )
        return user

allow_admin = RoleChecker([Role.ADMIN])
allow_analyst = RoleChecker([Role.ADMIN, Role.ANALYST])
allow_viewer = RoleChecker([Role.ADMIN, Role.ANALYST, Role.VIEWER])
