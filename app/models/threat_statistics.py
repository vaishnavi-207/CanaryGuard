from app.database.db import db
from app.models.base import BaseModel

class ThreatStatistics(BaseModel):
    """Daily/Hourly aggregated statistics for UI dashboard analytics."""
    __tablename__ = 'threat_statistics'

    record_date = db.Column(db.Date, nullable=False, unique=True, index=True)
    total_incidents = db.Column(db.Integer, default=0, nullable=False)
    canary_triggers = db.Column(db.Integer, default=0, nullable=False)
    entropy_violations = db.Column(db.Integer, default=0, nullable=False)
    processes_quarantined = db.Column(db.Integer, default=0, nullable=False)
    protected_files_count = db.Column(db.Integer, default=0, nullable=False)
