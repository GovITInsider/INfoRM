from datetime import timedelta

from fastapi import Response
from fastapi_login import LoginManager
from passlib.context import CryptContext

from inform.core.config import settings
from inform.core.database import SessionLocal
from inform.core.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SESSION_TTL = timedelta(minutes=settings.security.token_expires_minutes)
COOKIE_NAME = "access_token"


class NotAuthenticatedException(Exception):
    """Raised when a manage route is hit without a valid session."""


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


manager = LoginManager(
    secret=settings.security.secret_key,
    token_url="/manage/login",
    use_cookie=True,
    cookie_name=COOKIE_NAME,
    default_expiry=SESSION_TTL,
    not_authenticated_exception=NotAuthenticatedException,
)


@manager.user_loader()
def load_user(username: str):
    db = SessionLocal()
    try:
        return db.query(User).filter(User.username == username).first()
    finally:
        db.close()


def issue_session(response: Response, username: str) -> None:
    """Set an HttpOnly session cookie. Expiry matches token_expires_minutes (default 8 hours)."""
    token = manager.create_access_token(data={"sub": username})
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=int(SESSION_TTL.total_seconds()),
        path="/",
    )


def clear_session(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def username_from_token(token: str | None) -> str | None:
    if not token:
        return None
    try:
        payload = manager._get_payload(token)
        return payload.get("sub")
    except Exception:
        return None
