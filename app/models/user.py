from app.database.db import db
from app.models.base import BaseModel

class User(BaseModel):
    """User account model for admin/analyst authentication."""
    __tablename__ = 'users'

    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), default='analyst', nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
