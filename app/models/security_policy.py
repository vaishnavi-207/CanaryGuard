from app.database.db import db
from app.models.base import BaseModel

class SecurityPolicy(BaseModel):
    """Enforcement policy rules."""
    __tablename__ = 'security_policies'

    name = db.Column(db.String(128), unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    policy_type = db.Column(db.String(64), nullable=False) # ENTROPY_CHECK, CANARY_TRIGGER, BURST_RATE
    config_json = db.Column(db.Text, nullable=True)
    action_type = db.Column(db.String(64), default='QUARANTINE', nullable=False) # QUARANTINE, ALERT_ONLY, BLOCK_PROCESS
