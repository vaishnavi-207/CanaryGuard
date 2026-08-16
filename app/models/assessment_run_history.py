from datetime import datetime
from app.database.db import db
from app.models.base import BaseModel


class AssessmentRunHistory(BaseModel):
    """Readiness Assessment Run History storing historical snapshots."""
    __tablename__ = 'assessment_run_histories'

    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False, index=True)
    overall_score = db.Column(db.Float, nullable=False, default=0.0)
    maturity_level = db.Column(db.String(64), nullable=True)
    run_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    snapshot_json = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<AssessmentRunHistory Assessment #{self.assessment_id} Score: {self.overall_score}>"
