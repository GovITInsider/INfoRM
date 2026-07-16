from fastapi_login import LoginManager
from passlib.context import CryptContext
from inform.core.config import settings
from inform.core.database import SessionLocal
from inform.core.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

manager = LoginManager(
    secret=settings.security.secret_key,
    token_url="/manage/login",
    use_cookie=True,
    cookie_name="access_token"
)

@manager.user_loader()
def load_user(username: str):
    db = SessionLocal()
    try:
        return db.query(User).filter(User.username == username).first()
    finally:
        db.close()
