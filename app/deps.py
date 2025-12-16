from datetime import datetime

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.model import User
from app.schemas import SystemUser, TokenPayload
from app.utils import ALGORITHM, JWT_SECRET_KEY

reusable_auth = OAuth2PasswordBearer(
    tokenUrl="/login",
    scheme_name="JWT",
)


async def get_current_user(
    token: str = Depends(reusable_auth), db: Session = Depends(get_db)
) -> SystemUser:
    try:
        if not JWT_SECRET_KEY:
            raise ValueError("JWT_SECRET_KEY is not set")

        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])

        token_data = TokenPayload(**payload)

        print(token_data)

        if (
            token_data.exp is None
            or datetime.fromtimestamp(token_data.exp) < datetime.now()
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except (JWTError, ValidationError) as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    user = db.execute(
        select(User).where(User.email == token_data.sub)
    ).scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return SystemUser(
        id=user.id,
        email=user.email,
        password=user.password,
    )
