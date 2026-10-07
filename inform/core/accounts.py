"""Management accounts.

Anyone who is signed in can manage the network. Only an account manager can
create, remove, or reset other accounts. The cap is 10 accounts in total.
"""

import logging
import re

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from inform.core.auth import hash_password, verify_password
from inform.core.models import User

logger = logging.getLogger("inform.accounts")

MAX_ACCOUNTS = 10
USERNAME_RE = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")


class AccountError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def normalize_username(username: str | None) -> str:
    return (username or "").strip().lower()


def validate_new_username(username: str | None) -> str:
    normalized = normalize_username(username)
    if not USERNAME_RE.match(normalized):
        raise AccountError(
            "Usernames are 2 to 32 characters, start with a letter, and use "
            "lowercase letters, digits, or . _ -."
        )
    return normalized


def validate_password(password: str | None) -> str:
    password = password or ""
    if len(password) < 8 or len(password) > 200 or any(ord(ch) < 32 for ch in password):
        raise AccountError("Passwords are 8 to 200 characters.")
    return password


def list_accounts(db) -> list[User]:
    return db.query(User).order_by(User.username).all()


def _require_manager(actor: User | None) -> None:
    if actor is None or not actor.is_account_manager:
        raise AccountError("Only an account manager can do that.")


def _manager_count(db) -> int:
    return (
        db.query(func.count(User.id))
        .filter(User.is_account_manager.is_(True))
        .scalar()
        or 0
    )


def create_account(
    db,
    username: str | None,
    password: str | None,
    *,
    account_manager: bool,
    actor: User | None = None,
) -> User:
    """Add an account. actor=None is the create-admin recovery path and must be a manager."""
    normalized = validate_new_username(username)
    password = validate_password(password)
    if actor is None:
        if not account_manager:
            raise AccountError("Only an account manager can do that.")
    else:
        _require_manager(actor)

    try:
        count = db.query(func.count(User.id)).scalar() or 0
        if count >= MAX_ACCOUNTS:
            raise AccountError(
                f"The team is limited to {MAX_ACCOUNTS} accounts. Remove one to add another."
            )
        existing = db.query(User.id).filter(User.username == normalized).first()
        if existing:
            raise AccountError("That username is already in use.")
        user = User(
            username=normalized,
            hashed_password=hash_password(password),
            is_account_manager=bool(account_manager),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    except AccountError:
        db.rollback()
        raise
    except IntegrityError:
        db.rollback()
        raise AccountError("That username is already in use.") from None

    logger.info(
        "created account username=%s account_manager=%s by=%s",
        user.username,
        bool(user.is_account_manager),
        getattr(actor, "username", None) or "create-admin",
    )
    return user


def remove_account(db, actor: User, user_id: int) -> None:
    _require_manager(actor)
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise AccountError("That account is already gone.")
    if target.id == actor.id:
        raise AccountError("You cannot remove the account you are signed in as.")
    if target.is_account_manager and _manager_count(db) <= 1:
        raise AccountError("At least one account manager has to remain.")
    username = target.username
    db.delete(target)
    db.commit()
    logger.info("removed account username=%s by=%s", username, actor.username)


def set_account_manager(db, actor: User, user_id: int, account_manager: bool) -> None:
    _require_manager(actor)
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise AccountError("That account is already gone.")
    account_manager = bool(account_manager)
    if bool(target.is_account_manager) == account_manager:
        return
    if target.is_account_manager and not account_manager and _manager_count(db) <= 1:
        raise AccountError("At least one account manager has to remain.")
    username = target.username
    actor_name = actor.username
    target.is_account_manager = account_manager
    db.commit()
    logger.info(
        "set account_manager=%s username=%s by=%s",
        account_manager,
        username,
        actor_name,
    )


def reset_password(db, actor: User, user_id: int, password: str | None) -> None:
    _require_manager(actor)
    password = validate_password(password)
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise AccountError("That account is already gone.")
    username = target.username
    actor_name = actor.username
    target.hashed_password = hash_password(password)
    db.commit()
    logger.info("reset password username=%s by=%s", username, actor_name)


def change_own_password(
    db,
    actor: User,
    current_password: str | None,
    new_password: str | None,
    confirm_password: str | None,
) -> None:
    new_password = new_password or ""
    confirm_password = confirm_password or ""
    if new_password != confirm_password:
        raise AccountError("The new password and the confirmation do not match.")
    new_password = validate_password(new_password)
    target = db.query(User).filter(User.id == actor.id).first()
    if target is None:
        raise AccountError("That account is already gone.")
    if not verify_password(current_password or "", target.hashed_password):
        raise AccountError("The current password does not match.")
    username = target.username
    target.hashed_password = hash_password(new_password)
    db.commit()
    logger.info("changed own password username=%s", username)
