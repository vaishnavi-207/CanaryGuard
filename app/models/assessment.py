from app.database.db import db
from app.models.base import BaseModel


class Assessment(BaseModel):
    """Readiness Assessment model tracking organization posture and maturity."""
    __tablename__ = 'assessments'

    org_name = db.Column(db.String(256), nullable=False)
    org_size = db.Column(db.String(64), nullable=False, default='medium')  # small, medium, large, enterprise
    industry = db.Column(db.String(128), nullable=True)
    assessor_name = db.Column(db.String(128), nullable=True)
    status = db.Column(db.String(32), nullable=False, default='draft')  # draft, complete
    overall_score = db.Column(db.Float, nullable=True, default=0.0)
    maturity_level = db.Column(db.String(64), nullable=True, default='Initial')  # Initial, Developing, Defined, Managed, Optimized

    # Relationships
    domains = db.relationship('AssessmentDomain', backref='assessment', cascade='all, delete-orphan', lazy=True)
    run_histories = db.relationship('AssessmentRunHistory', backref='assessment', cascade='all, delete-orphan', lazy=True)

    def __repr__(self):
        return f"<Assessment #{self.id} {self.org_name} ({self.status})>"
