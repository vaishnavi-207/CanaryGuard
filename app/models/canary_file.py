from app.database.db import db
from app.models.base import BaseModel

class CanaryFile(BaseModel):
    """Canary Decoy File tracking model."""
    __tablename__ = 'canary_files'

    filename = db.Column(db.String(256), nullable=False)
    file_path = db.Column(db.String(512), unique=True, nullable=False, index=True)
    directory = db.Column(db.String(512), nullable=False)
    original_hash = db.Column(db.String(128), nullable=False)
    current_hash = db.Column(db.String(128), nullable=False)
    file_size_bytes = db.Column(db.Integer, nullable=False)
    is_hidden = db.Column(db.Boolean, default=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    trigger_count = db.Column(db.Integer, default=0, nullable=False)
    last_triggered_at = db.Column(db.DateTime, nullable=True)
