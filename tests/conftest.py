import pytest
import os
import shutil
from pathlib import Path
from app import create_app
from app.database.db import db
from config import TestingConfig

@pytest.fixture
def app():
    """Create and configure a clean Flask app for testing."""
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def temp_dir(tmp_path):
    """Provides a clean temporary directory for filesystem testing."""
    d = tmp_path / "test_dir"
    d.mkdir()
    return str(d)
