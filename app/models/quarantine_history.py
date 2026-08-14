from app.database.db import db
from app.models.base import BaseModel

class QuarantineHistory(BaseModel):
    """Log of quarantined processes and isolated files."""
    __tablename__ = 'quarantine_history'

    process_id = db.Column(db.Integer, nullable=True)
    process_name = db.Column(db.String(256), nullable=False)
    executable_path = db.Column(db.String(512), nullable=True)
    target_file_path = db.Column(db.String(512), nullable=True)
    quarantined_file_path = db.Column(db.String(512), nullable=True)
    reason = db.Column(db.String(256), nullable=False)
    threat_score = db.Column(db.Float, nullable=False, default=1.0)
    status = db.Column(db.String(64), default='QUARANTINED', nullable=False) # QUARANTINED, RESTORED, DELETED
