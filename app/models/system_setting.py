from app.database.db import db
from app.models.base import BaseModel

class SystemSetting(BaseModel):
    """Dynamic key-value settings table."""
    __tablename__ = 'system_settings'

    key = db.Column(db.String(128), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=False)
    data_type = db.Column(db.String(32), default='string', nullable=False) # string, float, int, bool, json
    description = db.Column(db.Text, nullable=True)
