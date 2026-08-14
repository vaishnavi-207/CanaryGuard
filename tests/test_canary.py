import os
import shutil
import tempfile
import unittest
from app import create_app
from app.database.db import db
from app.canary.canary_engine import CanaryDeploymentEngine
from app.models.canary_file import CanaryFile

class TestCanaryEngine(unittest.TestCase):
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

    def test_canary_deployment(self):
        records = CanaryDeploymentEngine.deploy_canaries_in_directory(self.test_dir)
        self.assertGreater(len(records), 0)
        for r in records:
            self.assertTrue(os.path.exists(r['file_path']))

        canary_db_count = CanaryFile.query.count()
        self.assertEqual(canary_db_count, len(records))

    def test_canary_modification_detection(self):
        records = CanaryDeploymentEngine.deploy_canaries_in_directory(self.test_dir)
        target_canary = records[0]['file_path']

        with open(target_canary, 'ab') as f:
            f.write(b"TAMPERED_RANSOMWARE_PAYLOAD")

        alert = CanaryDeploymentEngine.verify_canary_integrity(target_canary)
        self.assertIsNotNone(alert)
        self.assertEqual(alert['event'], 'CANARY_MODIFIED')

if __name__ == '__main__':
    unittest.main()
