from datetime import datetime, timezone, timedelta
from app.database.db import db

IST = timezone(timedelta(hours=5, minutes=30))

def get_current_ist_time():
    return datetime.now(timezone.utc)

class BaseModel(db.Model):
    """Abstract base model with auto timestamping and primary key."""
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_at = db.Column(db.DateTime, default=get_current_ist_time, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=get_current_ist_time, onupdate=get_current_ist_time, nullable=False)

    def to_dict(self):
        """Generic dictionary serializer for API endpoints."""
        res = {}
        for col in self.__table__.columns:
            val = getattr(self, col.name)
            if isinstance(val, datetime):
                val = val.isoformat()
            res[col.name] = val
        return res
