from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.deps import get_current_user
from app.model import User
from app.schemas import TokenSchema, UserAuth, UserOut
from app.utils import (
    create_access_token,
    create_refresh_token,
    get_hashed_password,
    verify_password,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup code can go here
    Base.metadata.create_all(bind=engine)
    yield
    # Any shutdown code can go here


app = FastAPI(lifespan=lifespan)


@app.post(
    "/signup",
    summary="Create new user",
    response_model=UserOut,
)
async def create_user(data: UserAuth, db: Session = Depends(get_db)):
    user = db.execute(
        select(User).filter(User.email == data.email)
    ).scalar_one_or_none()

    if user is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    hashed_password = get_hashed_password(data.password)
    user = User(email=data.email, password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserOut(id=user.id, email=user.email)


@app.post(
    "/login", summary="Create access and refresh token", response_model=TokenSchema
)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = db.execute(
        select(User).filter(User.email == form_data.username)
    ).scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password",
        )

    hashed_password = user.password

    if not verify_password(form_data.password, hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password",
        )
    return {
        "access_token": create_access_token(user.email),
        "refresh_token": create_refresh_token(user.email),
    }


@app.get(
    "/me", summary="Get details of currently logged in user", response_model=UserOut
)
async def get_me(user: User = Depends(get_current_user)):
    return user
