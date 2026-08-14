from app.database.db import db
from app.models.base import BaseModel

class ActivityLog(BaseModel):
    """System activity audit log."""
    __tablename__ = 'activity_logs'

    category = db.Column(db.String(64), nullable=False, index=True) # SYSTEM, USER_ACTION, SECURITY, MONITOR
    action = db.Column(db.String(128), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
