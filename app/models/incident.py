from app.database.db import db
from app.models.base import BaseModel
import json

RECOVERY_STAGES = [
    'Detected',
    'Contained',
    'Recovery Assessment',
    'Recovery In Progress',
    'Recovered'
]

RECOVERY_CHECKLIST_ITEMS = [
    'Threat contained',
    'Affected systems/files identified',
    'Backup availability verified',
    'Recovery point identified',
    'Recovery procedure available',
    'Restoration initiated',
    'Restoration verified',
    'System operational',
    'Post-incident assessment completed'
]

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
    status = db.Column(db.String(64), default='Detected', nullable=False, index=True) # Detected, Contained, Recovery Assessment, Recovery In Progress, Recovered, ACTIVE, RESOLVED
    confidence_score = db.Column(db.Float, default=0.0, nullable=False)
    description = db.Column(db.Text, nullable=True)
    recovery_notes = db.Column(db.Text, nullable=True)

    contained_at = db.Column(db.DateTime, nullable=True)
    recovered_at = db.Column(db.DateTime, nullable=True)

    @property
    def rto_minutes(self):
        if self.contained_at and self.recovered_at:
            delta = self.recovered_at - self.contained_at
            return round(delta.total_seconds() / 60, 1)
        return None

    def to_dict(self):
        res = super().to_dict()
        res['rto_minutes'] = self.rto_minutes
        return res

    def get_recovery_checklist(self):
        """Parse JSON checklist stored in recovery_notes or generate defaults."""
        if self.recovery_notes:
            try:
                data = json.loads(self.recovery_notes)
                if isinstance(data, dict) and 'checklist' in data:
                    return data['checklist']
            except Exception:
                pass
        
        is_contained = self.status in ['Contained', 'Recovery Assessment', 'Recovery In Progress', 'Recovered', 'RESOLVED']
        is_assessment = self.status in ['Recovery Assessment', 'Recovery In Progress', 'Recovered', 'RESOLVED']
        is_in_progress = self.status in ['Recovery In Progress', 'Recovered', 'RESOLVED']
        is_recovered = self.status in ['Recovered', 'RESOLVED']

        return {
            'Threat contained': is_contained or self.action_taken in ['QUARANTINED', 'TERMINATED'],
            'Affected systems/files identified': bool(self.file_path),
            'Backup availability verified': is_assessment,
            'Recovery point identified': is_assessment,
            'Recovery procedure available': is_assessment,
            'Restoration initiated': is_in_progress,
            'Restoration verified': is_recovered,
            'System operational': is_recovered,
            'Post-incident assessment completed': is_recovered
        }

    def get_recovery_notes_text(self):
        """Extract freeform text from recovery_notes JSON or return raw text."""
        if self.recovery_notes:
            try:
                data = json.loads(self.recovery_notes)
                if isinstance(data, dict) and 'notes' in data:
                    return data.get('notes', '')
            except Exception:
                return self.recovery_notes
        return ''
