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

    def test_recovery_readiness_assessment(self):
        from app.services.assessment_service import AssessmentService
        assessment_id = AssessmentService.create_assessment(
            org_name="Test Enterprise",
            org_size="medium",
            industry="Technology & Software",
            assessor_name="Test Auditor"
        )
        self.assertIsNotNone(assessment_id)

        breakdown = AssessmentService.get_score_breakdown(assessment_id)
        recover_domain = next((d for d in breakdown['domains'] if d['domain_code'] == 'RECOVER'), None)
        self.assertIsNotNone(recover_domain)
        self.assertEqual(recover_domain['domain_name'], 'Business Continuity & Disaster Recovery')

        # Verify all 9 recovery controls exist
        control_codes = [c['control_code'] for c in recover_domain['controls']]
        expected_recovery_controls = [
            'backup_availability',
            'backup_frequency',
            'backup_isolation',
            'recovery_procedure_availability',
            'disaster_recovery_plan',
            'rto_readiness',
            'rpo_readiness',
            'restoration_verification',
            'post_incident_recovery'
        ]
        for ctrl_code in expected_recovery_controls:
            self.assertIn(ctrl_code, control_codes)

        # Submit answers and verify Recovery Readiness score calculation
        answers = {ctrl: 'implemented' for ctrl in control_codes}
        updated_breakdown = AssessmentService.submit_answers(assessment_id, answers)
        updated_recover = next((d for d in updated_breakdown['domains'] if d['domain_code'] == 'RECOVER'), None)
        self.assertIsNotNone(updated_recover)
        self.assertGreaterEqual(updated_recover['score'], 80.0)

if __name__ == '__main__':
    unittest.main()
