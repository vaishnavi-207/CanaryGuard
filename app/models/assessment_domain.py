from app.database.db import db
from app.models.base import BaseModel


class AssessmentDomain(BaseModel):
    """Readiness Assessment Domain model grouping control frameworks."""
    __tablename__ = 'assessment_domains'

    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False, index=True)
    domain_name = db.Column(db.String(256), nullable=False)
    domain_code = db.Column(db.String(64), nullable=False)  # IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER, PEOPLE
    score = db.Column(db.Float, nullable=False, default=0.0)  # 0.0 - 100.0
    weight = db.Column(db.Float, nullable=False, default=1.0)

    # Relationships
    controls = db.relationship('AssessmentControl', backref='domain', cascade='all, delete-orphan', lazy=True)

    def __repr__(self):
        return f"<AssessmentDomain {self.domain_code} Score: {self.score}>"
