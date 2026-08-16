from app.database.db import db
from app.models.base import BaseModel


class AssessmentControl(BaseModel):
    """Readiness Assessment Control model storing individual posture controls."""
    __tablename__ = 'assessment_controls'

    domain_id = db.Column(db.Integer, db.ForeignKey('assessment_domains.id'), nullable=False, index=True)
    control_code = db.Column(db.String(64), nullable=False)
    control_title = db.Column(db.String(256), nullable=False)
    control_description = db.Column(db.Text, nullable=True)
    why_it_matters = db.Column(db.Text, nullable=True)
    maturity_answer = db.Column(db.String(64), nullable=False, default='not_implemented')  # not_implemented, partial, implemented, optimized
    score_value = db.Column(db.Float, nullable=False, default=0.0)
    auto_detected = db.Column(db.Boolean, nullable=False, default=False)
    auto_evidence = db.Column(db.Text, nullable=True)
    remediation_tip = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<AssessmentControl {self.control_code} ({self.maturity_answer})>"
