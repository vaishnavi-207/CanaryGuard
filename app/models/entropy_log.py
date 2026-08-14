from app.database.db import db
from app.models.base import BaseModel

class EntropyLog(BaseModel):
    """Historical Shannon Entropy Calculation record."""
    __tablename__ = 'entropy_logs'

    file_path = db.Column(db.String(512), nullable=False, index=True)
    entropy = db.Column(db.Float, nullable=False)
    threshold = db.Column(db.Float, nullable=False)
    exceeded_threshold = db.Column(db.Boolean, nullable=False, default=False)
    file_size_bytes = db.Column(db.Integer, nullable=False)
    event_type = db.Column(db.String(64), nullable=False) # MODIFIED, CREATED
    process_id = db.Column(db.Integer, nullable=True)
