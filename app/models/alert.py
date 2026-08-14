from app.database.db import db
from app.models.base import BaseModel

class Alert(BaseModel):
    """Real-time Security Alert model."""
    __tablename__ = 'alerts'

    alert_type = db.Column(db.String(64), nullable=False, index=True) # CANARY_TRIGGER, HIGH_ENTROPY, QUARANTINE_EXECUTED, MONITORING_STARTED
    severity = db.Column(db.String(32), default='HIGH', nullable=False) # CRITICAL, HIGH, WARNING, INFO
    title = db.Column(db.String(256), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    source = db.Column(db.String(64), default='DetectionEngine', nullable=False)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=True)
