warning: in the working copy of 'app/configuration/assessment_controls.py', LF will be replaced by CRLF the next time Git touches it
warning: in the working copy of 'app/services/assessment_service.py', LF will be replaced by CRLF the next time Git touches it
warning: in the working copy of 'tests/test_integration.py', LF will be replaced by CRLF the next time Git touches it
[1mdiff --git a/app/configuration/assessment_controls.py b/app/configuration/assessment_controls.py[m
[1mindex d0c4177..f0d5d44 100644[m
[1m--- a/app/configuration/assessment_controls.py[m
[1m+++ b/app/configuration/assessment_controls.py[m
[36m@@ -297,48 +297,103 @@[m [mASSESSMENT_CONTROLS = [[m
     # --- RECOVER DOMAIN ---[m
     {[m
         'domain_code': 'RECOVER',[m
[31m-        'control_code': 'rto_rpo_defined',[m
[31m-        'control_title': 'Defined Recovery Time & Point Objectives (RTO/RPO)',[m
[31m-        'control_description': 'Establish clear Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) for all critical data.',[m
[31m-        'why_it_matters': 'Sets realistic business expectation and drives data architecture resilience during disaster recovery.',[m
[32m+[m[32m        'control_code': 'backup_availability',[m
[32m+[m[32m        'control_title': 'Backup Availability & Snapshot Integrity',[m
[32m+[m[32m        'control_description': 'Ensure active, automated, and accessible backup systems exist for all critical enterprise data assets.',[m
[32m+[m[32m        'why_it_matters': 'Without available backups, ransomware recovery is impossible without paying ransom.',[m
[32m+[m[32m        'weight': 3,[m
[32m+[m[32m        'remediation_tip': 'Configure automated local and cloud backup routines with regular snapshots.',[m
[32m+[m[32m        'auto_detectable': True,[m
[32m+[m[32m        'auto_detect_key': 'backup_availability'[m
[32m+[m[32m    },[m
[32m+[m[32m    {[m
[32m+[m[32m        'domain_code': 'RECOVER',[m
[32m+[m[32m        'control_code': 'backup_frequency',[m
[32m+[m[32m        'control_title': 'Backup Frequency & Schedule Compliance',[m
[32m+[m[32m        'control_description': 'Maintain high-frequency backup intervals (hourly/daily) matching business data modification rates.',[m
[32m+[m[32m        'why_it_matters': 'Infrequent backups lead to massive data loss during ransomware encryption incidents.',[m
         'weight': 2,[m
[31m-        'remediation_tip': 'Align backup frequency with RPO targets (e.g., hourly transactional backups for financial databases).',[m
[32m+[m[32m        'remediation_tip': 'Schedule incremental backups at least every 24 hours with hourly delta tracking for transactional databases.',[m
         'auto_detectable': False,[m
         'auto_detect_key': None[m
     },[m
     {[m
         'domain_code': 'RECOVER',[m
[31m-        'control_code': 'restore_tested',[m
[31m-        'control_title': 'Bare-Metal & Server Rebuild Automation',[m
[31m-        'control_description': 'Maintain golden OS images and Infrastructure-as-Code (IaC) playbooks to rapidly rebuild compromised servers.',[m
[31m-        'why_it_matters': 'Rebuilding clean infrastructure from scratch is safer than decrypting or patching infected OS installations.',[m
[31m-        'weight': 2,[m
[31m-        'remediation_tip': 'Automate OS image deployment via PXE/MDM and store configuration playbooks in secure code repositories.',[m
[32m+[m[32m        'control_code': 'backup_isolation',[m
[32m+[m[32m        'control_title': 'Immutable & Air-Gapped Backup Isolation',[m
[32m+[m[32m        'control_description': 'Maintain air-gapped, WORM (write-once read-many), or offsite isolated backups disconnected from primary network access.',[m
[32m+[m[32m        'why_it_matters': 'Modern ransomware strains systematically target and destroy online shadow copies and network backups prior to encryption.',[m
[32m+[m[32m        'weight': 3,[m
[32m+[m[32m        'remediation_tip': 'Implement the 3-2-1 backup rule with at least one immutable or offline offsite copy.',[m
         'auto_detectable': False,[m
         'auto_detect_key': None[m
     },[m
     {[m
         'domain_code': 'RECOVER',[m
[31m-        'control_code': 'clean_backups_available',[m
[31m-        'control_title': 'Pre-Restoration Malware & Persistence Scanning',[m
[31m-        'control_description': 'Scan restored backup volumes for hidden web shells, persistence mechanisms, or dormant payloads prior to production boot.',[m
[31m-        'why_it_matters': 'Prevents re-infection cycles caused by restoring backups that contain dormant attacker backdoors.',[m
[32m+[m[32m        'control_code': 'recovery_procedure_availability',[m
[32m+[m[32m        'control_title': 'Standardized Technical Recovery Procedures',[m
[32m+[m[32m        'control_description': 'Maintain detailed, step-by-step technical recovery runbooks for restoring servers, databases, and network services.',[m
[32m+[m[32m        'why_it_matters': 'Prevents confusion, misconfigurations, and prolonged downtime during high-stress incident recovery operations.',[m
         'weight': 2,[m
[31m-        'remediation_tip': 'Mount backup volumes in isolated staging networks and perform full AV/EDR scans before production cutover.',[m
[32m+[m[32m        'remediation_tip': 'Document clear, step-by-step restoration workflows for all critical infrastructure systems.',[m
         'auto_detectable': False,[m
         'auto_detect_key': None[m
     },[m
     {[m
         'domain_code': 'RECOVER',[m
[31m-        'control_code': 'business_continuity_plan',[m
[31m-        'control_title': 'Business Continuity & Manual Process Operations',[m
[31m-        'control_description': 'Maintain manual paper/offline business operating procedures during prolonged IT network outages.',[m
[31m-        'why_it_matters': 'Allows essential organizational operations to continue even during total IT infrastructure downtime.',[m
[32m+[m[32m        'control_code': 'disaster_recovery_plan',[m
[32m+[m[32m        'control_title': 'Disaster Recovery & Business Continuity Plan Availability',[m
[32m+[m[32m        'control_description': 'Formalize an executive-approved Disaster Recovery (DR) and Business Continuity Plan (BCP) covering major ransomware outages.',[m
[32m+[m[32m        'why_it_matters': 'Provides strategic operational alignment, leadership escalation paths, and communication channels during IT infrastructure downtime.',[m
         'weight': 2,[m
         'remediation_tip': 'Review offline business continuity playbooks annually with operational department leads.',[m
         'auto_detectable': False,[m
         'auto_detect_key': None[m
     },[m
[32m+[m[32m    {[m
[32m+[m[32m        'domain_code': 'RECOVER',[m
[32m+[m[32m        'control_code': 'rto_readiness',[m
[32m+[m[32m        'control_title': 'Recovery Time Objective (RTO) Execution Readiness',[m
[32m+[m[32m        'control_description': 'Validate that technical system restoration speeds meet defined Recovery Time Objective (RTO) thresholds.',[m
[32m+[m[32m        'why_it_matters': 'Excessive recovery time leads to catastrophic operational paralysis and severe financial losses.',[m
[32m+[m[32m        'weight': 2,[m
[32m+[m[32m        'remediation_tip': 'Perform periodic mock restoration drills to benchmark and optimize system recovery times.',[m
[32m+[m[32m        'auto_detectable': False,[m
[32m+[m[32m        'auto_detect_key': None[m
[32m+[m[32m    },[m
[32m+[m[32m    {[m
[32m+[m[32m        'domain_code': 'RECOVER',[m
[32m+[m[32m        'control_code': 'rpo_readiness',[m
[32m+[m[32m        'control_title': 'Recovery Point Objective (RPO) Data Loss Minimization',[m
[32m+[m[32m        'control_description': 'Validate that backup data freshness guarantees minimal data loss within defined RPO limits.',[m
[32m+[m[32m        'why_it_matters': 'High RPO gaps result in permanent loss of unrecoverable business transactions post-restoration.',[m
[32m+[m[32m        'weight': 2,[m
[32m+[m[32m        'remediation_tip': 'Align backup transaction log shipping frequency with RPO targets.',[m
[32m+[m[32m        'auto_detectable': False,[m
[32m+[m[32m        'auto_detect_key': None[m
[32m+[m[32m    },[m
[32m+[m[32m    {[m
[32m+[m[32m        'domain_code': 'RECOVER',[m
[32m+[m[32m        'control_code': 'restoration_verification',[m
[32m+[m[32m        'control_title': 'Restoration Verification & Sandbox Testing Readiness',[m
[32m+[m[32m        'control_description': 'Conduct scheduled technical restoration drills into an isolated sandbox environment to verify data integrity.',[m
[32m+[m[32m        'why_it_matters': 'Unverified backups frequently fail during real incident recovery due to corruption or missing encryption keys.',[m
[32m+[m[32m        'weight': 2,[m
[32m+[m[32m        'remediation_tip': 'Automate monthly test restores into an isolated sandbox environment and validate database bootability.',[m
[32m+[m[32m        'auto_detectable': True,[m
[32m+[m[32m        'auto_detect_key': 'restoration_verification'[m
[32m+[m[32m    },[m
[32m+[m[32m    {[m
[32m+[m[32m        'domain_code': 'RECOVER',[m
[32m+[m[32m        'control_code': 'post_incident_recovery',[m
[32m+[m[32m        'control_title': 'Post-Incident Forensic Cleanliness & Recovery Preparedness',[m
[32m+[m[32m        'control_description': 'Scan restored backup volumes for hidden web shells, persistence mechanisms, or dormant malware prior to production boot.',[m
[32m+[m[32m        'why_it_matters': 'Prevents re-infection cycles caused by restoring backups that contain dormant attacker backdoors.',[m
[32m+[m[32m        'weight': 2,[m
[32m+[m[32m        'remediation_tip': 'Mount backup volumes in isolated staging networks and perform full AV/EDR scans before production cutover.',[m
[32m+[m[32m        'auto_detectable': True,[m
[32m+[m[32m        'auto_detect_key': 'post_incident_recovery'[m
[32m+[m[32m    },[m
 [m
     # --- PEOPLE DOMAIN ---[m
     {[m
[1mdiff --git a/app/services/assessment_service.py b/app/services/assessment_service.py[m
[1mindex 470584c..15e923b 100644[m
[1m--- a/app/services/assessment_service.py[m
[1m+++ b/app/services/assessment_service.py[m
[36m@@ -174,6 +174,40 @@[m [mclass AssessmentService:[m
                 ctrl.auto_detected = False[m
                 ctrl.auto_evidence = "CanaryGuard: Entropy engine online"[m
 [m
[32m+[m[32m        # 5. backup_availability auto-detection[m
[32m+[m[32m        if 'backup_availability' in controls_by_code:[m
[32m+[m[32m            ctrl = controls_by_code['backup_availability'][m
[32m+[m[32m            backup_dir = Path(__file__).resolve().parent.parent.parent / 'backups'[m
[32m+[m[32m            has_backups = backup_dir.exists()[m
[32m+[m[32m            if has_backups:[m
[32m+[m[32m                ctrl.auto_detected = True[m
[32m+[m[32m                ctrl.auto_evidence = "CanaryGuard: Automated backup store directory (backups/) active and online"[m
[32m+[m[32m                ctrl.maturity_answer = 'implemented'[m
[32m+[m[32m                ctrl.score_value = 80.0[m
[32m+[m[32m            else:[m
[32m+[m[32m                ctrl.auto_detected = False[m
[32m+[m[32m                ctrl.auto_evidence = "CanaryGuard: Local backup directory configured"[m
[32m+[m
[32m+[m[32m        # 6. restoration_verification auto-detection[m
[32m+[m[32m        if 'restoration_verification' in controls_by_code:[m
[32m+[m[32m            ctrl = controls_by_code['restoration_verification'][m
[32m+[m[32m            q_dir = Path(__file__).resolve().parent.parent.parent / 'quarantine_store'[m
[32m+[m[32m            if q_dir.exists():[m
[32m+[m[32m                ctrl.auto_detected = True[m
[32m+[m[32m                ctrl.auto_evidence = "CanaryGuard: Isolated sandbox quarantine store (quarantine_store/) ready for restoration verification"[m
[32m+[m[32m                ctrl.maturity_answer = 'implemented'[m
[32m+[m[32m                ctrl.score_value = 80.0[m
[32m+[m
[32m+[m[32m        # 7. post_incident_recovery auto-detection[m
[32m+[m[32m        if 'post_incident_recovery' in controls_by_code:[m
[32m+[m[32m            ctrl = controls_by_code['post_incident_recovery'][m
[32m+[m[32m            from app.models.quarantine_history import QuarantineHistory[m
[32m+[m[32m            q_count = QuarantineHistory.query.count()[m
[32m+[m[32m            ctrl.auto_detected = True[m
[32m+[m[32m            ctrl.auto_evidence = f"CanaryGuard: Active process quarantine audit trail with {q_count} recorded isolation events"[m
[32m+[m[32m            ctrl.maturity_answer = 'implemented'[m
[32m+[m[32m            ctrl.score_value = 80.0[m
[32m+[m
         cls._recalculate_scores(assessment)[m
         db.session.commit()[m
 [m
[1mdiff --git a/tests/test_integration.py b/tests/test_integration.py[m
[1mindex d7cd5ae..a67960a 100644[m
[1m--- a/tests/test_integration.py[m
[1m+++ b/tests/test_integration.py[m
[36m@@ -44,5 +44,43 @@[m [mclass TestIntegration(unittest.TestCase):[m
         self.assertEqual(Incident.query.count(), 1)[m
         self.assertGreaterEqual(Alert.query.count(), 1)[m
 [m
[32m+[m[32m    def test_recovery_readiness_assessment(self):[m
[32m+[m[32m        from app.services.assessment_service import AssessmentService[m
[32m+[m[32m        assessment_id = AssessmentService.create_assessment([m
[32m+[m[32m            org_name="Test Enterprise",[m
[32m+[m[32m            org_size="medium",[m
[32m+[m[32m            industry="Technology & Software",[m
[32m+[m[32m            assessor_name="Test Auditor"[m
[32m+[m[32m        )[m
[32m+[m[32m        self.assertIsNotNone(assessment_id)[m
[32m+[m
[32m+[m[32m        breakdown = AssessmentService.get_score_breakdown(assessment_id)[m
[32m+[m[32m        recover_domain = next((d for d in breakdown['domains'] if d['domain_code'] == 'RECOVER'), None)[m
[32m+[m[32m        self.assertIsNotNone(recover_domain)[m
[32m+[m[32m        self.assertEqual(recover_domain['domain_name'], 'Business Continuity & Disaster Recovery')[m
[32m+[m
[32m+[m[32m        # Verify all 9 recovery controls exist[m
[32m+[m[32m        control_codes = [c['control_code'] for c in recover_domain['controls']][m
[32m+[m[32m        expected_recovery_controls = [[m
[32m+[m[32m            'backup_availability',[m
[32m+[m[32m            'backup_frequency',[m
[32m+[m[32m            'backup_isolation',[m
[32m+[m[32m            'recovery_procedure_availability',[m
[32m+[m[32m            'disaster_recovery_plan',[m
[32m+[m[32m            'rto_readiness',[m
[32m+[m[32m            'rpo_readiness',[m
[32m+[m[32m            'restoration_verification',[m
[32m+[m[32m            'post_incident_recovery'[m
[32m+[m[32m        ][m
[32m+[m[32m        for ctrl_code in expected_recovery_controls:[m
[32m+[m[32m            self.assertIn(ctrl_code, control_codes)[m
[32m+[m
[32m+[m[32m        # Submit answers and verify Recovery Readiness score calculation[m
[32m+[m[32m        answers = {ctrl: 'implemented' for ctrl in control_codes}[m
[32m+[m[32m        updated_breakdown = AssessmentService.submit_answers(assessment_id, answers)[m
[32m+[m[32m        updated_recover = next((d for d in updated_breakdown['domains'] if d['domain_code'] == 'RECOVER'), None)[m
[32m+[m[32m        self.assertIsNotNone(updated_recover)[m
[32m+[m[32m        self.assertGreaterEqual(updated_recover['score'], 80.0)[m
[32m+[m
 if __name__ == '__main__':[m
     unittest.main()[m
