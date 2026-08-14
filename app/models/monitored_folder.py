from app.database.db import db
from app.models.base import BaseModel

class MonitoredFolder(BaseModel):
    """Monitored directories configuration and status."""
    __tablename__ = 'monitored_folders'

    folder_path = db.Column(db.String(512), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    recursive = db.Column(db.Boolean, default=True, nullable=False)
    canaries_deployed = db.Column(db.Boolean, default=False, nullable=False)
    file_count = db.Column(db.Integer, default=0, nullable=False)
    last_scanned_at = db.Column(db.DateTime, nullable=True)
