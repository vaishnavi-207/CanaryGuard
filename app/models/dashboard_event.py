from app.database.db import db
from app.models.base import BaseModel

class DashboardEvent(BaseModel):
    """Event log specifically designed for real-time WebSocket dashboard broadcasting."""
    __tablename__ = 'dashboard_events'

    event_name = db.Column(db.String(64), nullable=False, index=True)
    payload_json = db.Column(db.Text, nullable=False)
    is_broadcasted = db.Column(db.Boolean, default=True, nullable=False)
