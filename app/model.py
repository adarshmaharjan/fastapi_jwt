import uuid
from datetime import datetime

from sqlalchemy import TIMESTAMP, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import text

from app.database import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        index=True,
        unique=True,
        nullable=False,
        default=uuid.uuid4,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        index=True,
        unique=True,
        nullable=False,
    )
    password: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
