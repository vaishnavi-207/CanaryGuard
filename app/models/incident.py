from app.database.db import db
from app.models.base import BaseModel

class Incident(BaseModel):
    """Incident log model storing detected ransomware/integrity events."""
    __tablename__ = 'incidents'

    threat_level = db.Column(db.String(32), nullable=False, default='CRITICAL', index=True) # LOW, MEDIUM, HIGH, CRITICAL
    file_path = db.Column(db.String(512), nullable=False)
    canary_triggered = db.Column(db.Boolean, default=False, nullable=False)
    entropy_value = db.Column(db.Float, nullable=True)
    process_id = db.Column(db.Integer, nullable=True)
    process_name = db.Column(db.String(256), nullable=True)
    executable_path = db.Column(db.String(512), nullable=True)
    action_taken = db.Column(db.String(128), default='QUARANTINED', nullable=False) # QUARANTINED, LOGGED, TERMINATED
    status = db.Column(db.String(64), default='ACTIVE', nullable=False, index=True) # ACTIVE, RESOLVED, FALSE_POSITIVE
    confidence_score = db.Column(db.Float, default=0.0, nullable=False)
    description = db.Column(db.Text, nullable=True)
    recovery_notes = db.Column(db.Text, nullable=True)
