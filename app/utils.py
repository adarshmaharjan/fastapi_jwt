import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from dotenv import load_dotenv
from jose import jwt
from passlib.context import CryptContext

load_dotenv()

# Load environment variables from .env file

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
ALGORITHM = "HS256"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_REFRESH_SECRET_KEY = os.getenv("JWT_REFRESH_SECRET_KEY")


def get_hashed_password(password: str) -> str:
    # Pre-hash with SHA256 to handle passwords longer than 72 bytes
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return password_context.hash(password_hash)


def verify_password(password: str, hashed_password: str) -> bool:
    # Pre-hash with SHA256 to match the hashing process
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return password_context.verify(password_hash, hashed_password)


def create_access_token(subject: str | Any, expires_delta: int | None = None):
    if expires_delta:
        expire_delta = datetime.now(tz=timezone.utc) + timedelta(minutes=expires_delta)
    else:
        expire_delta = datetime.now(tz=timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode = {"exp": expire_delta, "sub": str(subject)}

    if JWT_SECRET_KEY is None:
        raise ValueError("JWT_SECRET_KEY environment variable is not set")
    encode_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encode_jwt


def create_refresh_token(subject: str | Any, expire_delta: int | None = None):
    if expire_delta:
        expire = datetime.now(tz=timezone.utc) + timedelta(minutes=expire_delta)
    else:
        expire = datetime.now(tz=timezone.utc) + timedelta(
            minutes=REFRESH_TOKEN_EXPIRE_MINUTES
        )
    to_encode = {"exp": expire, "sub": str(subject)}

    if JWT_REFRESH_SECRET_KEY is None:
        raise ValueError("JWT_REFRESH_SECRET_KEY environment variable is not set")
    encode_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encode_jwt
