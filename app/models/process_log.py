from app.database.db import db
from app.models.base import BaseModel

class ProcessLog(BaseModel):
    """Process monitoring history and metadata."""
    __tablename__ = 'process_logs'

    pid = db.Column(db.Integer, nullable=False, index=True)
    parent_pid = db.Column(db.Integer, nullable=True)
    name = db.Column(db.String(256), nullable=False)
    executable_path = db.Column(db.String(512), nullable=True)
    cmdline = db.Column(db.Text, nullable=True)
    username = db.Column(db.String(128), nullable=True)
    cpu_percent = db.Column(db.Float, default=0.0)
    memory_percent = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(64), default='RUNNING')
    is_suspicious = db.Column(db.Boolean, default=False, nullable=False, index=True)
    suspicion_reason = db.Column(db.Text, nullable=True)
