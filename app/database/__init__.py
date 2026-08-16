from app.database.db import db


def init_db(app):
    """Initialize database extensions and auto-create all tables."""
    db.init_app(app)
    with app.app_context():
        import app.models  # Register models with SQLAlchemy metadata
        db.create_all()


def create_all_tables():
    """Explicit helper to trigger db.create_all()."""
    import app.models  # Register models with SQLAlchemy metadata
    db.create_all()
