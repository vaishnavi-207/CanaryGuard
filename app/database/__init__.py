from app.database.db import db


def init_db(app):
    """Initialize database extensions and auto-create all tables."""
    db.init_app(app)
    with app.app_context():
        import app.models  # Register models with SQLAlchemy metadata
        db.create_all()
        
        # Ensure new schema columns exist on existing SQLite databases
        try:
            inspector = db.inspect(db.engine)
            if 'incidents' in inspector.get_table_names():
                cols = [c['name'] for c in inspector.get_columns('incidents')]
                with db.engine.connect() as conn:
                    if 'contained_at' not in cols:
                        conn.execute(db.text("ALTER TABLE incidents ADD COLUMN contained_at DATETIME"))
                    if 'recovered_at' not in cols:
                        conn.execute(db.text("ALTER TABLE incidents ADD COLUMN recovered_at DATETIME"))
                    conn.commit()
        except Exception:
            pass


def create_all_tables():
    """Explicit helper to trigger db.create_all()."""
    import app.models  # Register models with SQLAlchemy metadata
    db.create_all()
