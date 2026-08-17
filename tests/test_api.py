import unittest
from app import create_app
from app.database.db import db

class TestAPIRoutes(unittest.TestCase):
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

    def test_get_status_api(self):
        response = self.client.get('/api/status')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'OK')

    def test_get_incidents_api(self):
        response = self.client.get('/api/incidents')
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    def test_get_canaries_api(self):
        response = self.client.get('/api/canaries')
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    def test_deploy_canaries_api(self):
        response = self.client.post('/api/deploy-canaries', json={})
        self.assertEqual(response.status_code, 200)
        self.assertIn('message', response.get_json())

    def test_settings_api(self):
        response = self.client.get('/api/settings')
        self.assertEqual(response.status_code, 200)
        update_res = self.client.post('/api/settings', json={'log_level': 'DEBUG'})
        self.assertEqual(update_res.status_code, 200)

    def test_incident_early_recovery_workflow(self):
        from app.models.incident import Incident
        inc = Incident(
            file_path="C:\\Monitored\\critical_db.mdf",
            threat_level="CRITICAL",
            canary_triggered=True,
            status="Detected"
        )
        db.session.add(inc)
        db.session.commit()

        # Step 1: Transition stage to Contained
        resp = self.client.post(f'/api/incidents/{inc.id}/recovery', json={
            'status': 'Contained',
            'checklist': {'Threat contained': True, 'Affected systems/files identified': True}
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['status'], 'Contained')

        # Step 2: Transition through Recovery Assessment -> Recovered
        resp2 = self.client.post(f'/api/incidents/{inc.id}/recovery', json={
            'status': 'Recovered',
            'checklist': {
                'Backup availability verified': True,
                'Recovery point identified': True,
                'Recovery procedure available': True,
                'Restoration initiated': True,
                'Restoration verified': True,
                'System operational': True,
                'Post-incident assessment completed': True
            }
        })
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.get_json()['status'], 'Recovered')

if __name__ == '__main__':
    unittest.main()
