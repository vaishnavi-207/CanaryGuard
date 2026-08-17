import unittest
from datetime import datetime, timezone, timedelta
from app import create_app
from app.database.db import db
from app.models.incident import Incident
from app.services.assessment_service import AssessmentService

class TestRecoveryTracking(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_rto_timestamp_tracking_and_property(self):
        now = datetime.now(timezone.utc)
        contained_time = now - timedelta(minutes=15)
        recovered_time = now

        inc = Incident(
            file_path="C:\\Monitored\\database.db",
            threat_level="CRITICAL",
            status="Detected"
        )
        db.session.add(inc)
        db.session.commit()

        self.assertIsNone(inc.rto_minutes)
        self.assertIsNone(inc.contained_at)
        self.assertIsNone(inc.recovered_at)

        # Update to Contained
        resp1 = self.client.post(f'/api/incidents/{inc.id}/recovery', json={'status': 'Contained'})
        self.assertEqual(resp1.status_code, 200)
        self.assertIsNotNone(inc.contained_at)
        self.assertIsNone(inc.recovered_at)
        self.assertIsNone(inc.rto_minutes)

        # Manually backdate contained_at to test exact RTO delta calculation
        inc.contained_at = contained_time
        db.session.commit()

        # Update to Recovered
        resp2 = self.client.post(f'/api/incidents/{inc.id}/recovery', json={'status': 'Recovered'})
        self.assertEqual(resp2.status_code, 200)
        self.assertIsNotNone(inc.recovered_at)
        self.assertAlmostEqual(inc.rto_minutes, 15.0, delta=0.2)

    def test_get_recovery_stats_api(self):
        # Initial empty state
        resp = self.client.get('/api/recovery/stats')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['recovery_rate'], 0.0)
        self.assertIsNone(data['avg_rto_minutes'])
        self.assertEqual(data['total_recovered'], 0)
        self.assertEqual(data['total_incidents'], 0)

        # Create two incidents: one active, one recovered with RTO
        inc1 = Incident(file_path="C:\\file1.docx", status="Detected")
        inc2 = Incident(
            file_path="C:\\file2.docx",
            status="Recovered",
            contained_at=datetime.now(timezone.utc) - timedelta(minutes=10),
            recovered_at=datetime.now(timezone.utc)
        )
        db.session.add_all([inc1, inc2])
        db.session.commit()

        resp2 = self.client.get('/api/recovery/stats')
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.get_json()
        self.assertEqual(data2['total_incidents'], 2)
        self.assertEqual(data2['total_recovered'], 1)
        self.assertEqual(data2['recovery_rate'], 50.0)
        self.assertEqual(data2['avg_rto_minutes'], 10.0)

    def test_assessment_recover_auto_detection(self):
        assessment_id = AssessmentService.create_assessment("Test Corp")
        
        # Add a recovered incident with RTO
        inc = Incident(
            file_path="C:\\server\\data.bin",
            status="Recovered",
            contained_at=datetime.now(timezone.utc) - timedelta(minutes=5),
            recovered_at=datetime.now(timezone.utc)
        )
        db.session.add(inc)
        db.session.commit()

        AssessmentService.auto_detect_controls(assessment_id)
        breakdown = AssessmentService.get_score_breakdown(assessment_id)
        
        recover_domain = next(d for d in breakdown['domains'] if d['domain_code'] == 'RECOVER')
        controls = {c['control_code']: c for c in recover_domain['controls']}

        rto_ctrl = controls.get('rto_rpo_defined') or controls.get('rto_readiness')
        self.assertIsNotNone(rto_ctrl)
        self.assertTrue(rto_ctrl['auto_detected'])
        self.assertIn("Actual RTO measured: 5.0 minutes", rto_ctrl['auto_evidence'])

        restore_ctrl = controls.get('restore_tested') or controls.get('restoration_verification')
        self.assertIsNotNone(restore_ctrl)
        self.assertTrue(restore_ctrl['auto_detected'])
        self.assertIn("System successfully recovered from 1 incidents", restore_ctrl['auto_evidence'])

if __name__ == '__main__':
    unittest.main()
