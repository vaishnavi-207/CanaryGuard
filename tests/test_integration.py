import os
import shutil
import tempfile
import unittest
from app import create_app
from app.database.db import db
from app.services.detection_engine import BehavioralDetectionEngine
from app.models.incident import Incident
from app.models.alert import Alert

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_full_detection_and_incident_logging(self):
        test_file = os.path.join(self.test_dir, "encrypted_test_doc.docx")
        with open(test_file, 'wb') as f:
            f.write(os.urandom(1024))

        event_data = {
            'event_type': 'MODIFIED',
            'src_path': test_file,
            'entropy': 7.8,
            'is_high_entropy': True,
            'canary_triggered': True,
            'is_burst': True,
            'pid': 99999,
            'process_name': 'mock_ransomware.exe'
        }

        res = BehavioralDetectionEngine.evaluate_and_respond(event_data, auto_quarantine=False)
        self.assertEqual(res['threat_level'], 'CRITICAL')
        self.assertGreaterEqual(res['confidence_score'], 80.0)
        self.assertEqual(Incident.query.count(), 1)
        self.assertGreaterEqual(Alert.query.count(), 1)

if __name__ == '__main__':
    unittest.main()
