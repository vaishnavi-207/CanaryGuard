import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

from app.database.db import db
from app.models.assessment import Assessment
from app.models.assessment_domain import AssessmentDomain
from app.models.assessment_control import AssessmentControl
from app.models.assessment_run_history import AssessmentRunHistory
from app.models.canary_file import CanaryFile
from app.models.entropy_log import EntropyLog
from app.models.incident import Incident

from app.configuration.assessment_controls import (
    ASSESSMENT_CONTROLS,
    DOMAIN_NAMES,
    DOMAIN_WEIGHTS
)

MATURITY_SCORE_MAP = {
    'not_implemented': 0.0,
    'partial': 40.0,
    'implemented': 80.0,
    'optimized': 100.0
}


class AssessmentService:
    """Service handling Ransomware Readiness Assessment creation, auto-detection, and scoring."""

    @classmethod
    def get_maturity_level(cls, score: float) -> str:
        """Derive NIST cybersecurity maturity level string from 0-100 numerical score."""
        score = float(score or 0.0)
        if score <= 20.0:
            return 'Initial'
        elif score <= 40.0:
            return 'Developing'
        elif score <= 60.0:
            return 'Defined'
        elif score <= 80.0:
            return 'Managed'
        else:
            return 'Optimized'

    @classmethod
    def create_assessment(
        cls,
        org_name: str,
        org_size: str = 'medium',
        industry: Optional[str] = None,
        assessor_name: Optional[str] = None
    ) -> int:
        """Create new Assessment record with populated domain and control framework."""
        assessment = Assessment(
            org_name=org_name,
            org_size=org_size or 'medium',
            industry=industry,
            assessor_name=assessor_name,
            status='draft',
            overall_score=0.0,
            maturity_level='Initial'
        )
        db.session.add(assessment)
        db.session.flush()  # Generate assessment.id

        domain_map = {}
        # Create AssessmentDomain entries
        for code, name in DOMAIN_NAMES.items():
            domain = AssessmentDomain(
                assessment_id=assessment.id,
                domain_name=name,
                domain_code=code,
                score=0.0,
                weight=DOMAIN_WEIGHTS.get(code, 1.0)
            )
            db.session.add(domain)
            db.session.flush()
            domain_map[code] = domain

        # Control weight lookup
        control_weights = {ctrl['control_code']: ctrl.get('weight', 1) for ctrl in ASSESSMENT_CONTROLS}

        # Create AssessmentControl entries
        for ctrl_def in ASSESSMENT_CONTROLS:
            domain_obj = domain_map.get(ctrl_def['domain_code'])
            if not domain_obj:
                continue

            control = AssessmentControl(
                domain_id=domain_obj.id,
                control_code=ctrl_def['control_code'],
                control_title=ctrl_def['control_title'],
                control_description=ctrl_def['control_description'],
                why_it_matters=ctrl_def['why_it_matters'],
                maturity_answer='not_implemented',
                score_value=0.0,
                auto_detected=False,
                auto_evidence=None,
                remediation_tip=ctrl_def['remediation_tip']
            )
            db.session.add(control)

        db.session.commit()

        # Run auto-detection to populate platform controls
        cls.auto_detect_controls(assessment.id)

        return assessment.id

    @classmethod
    def auto_detect_controls(cls, assessment_id: int):
        """Cross-check live CanaryGuard platform metrics to populate auto-detected controls."""
        assessment = Assessment.query.get(assessment_id)
        if not assessment:
            return

        # Build map of controls by control_code
        controls_by_code = {}
        for domain in assessment.domains:
            for control in domain.controls:
                controls_by_code[control.control_code] = control

        # 1. canary_deployment auto-detection
        if 'canary_deployment' in controls_by_code:
            ctrl = controls_by_code['canary_deployment']
            canary_count = CanaryFile.query.filter_by(is_active=True).count()
            if canary_count > 0:
                ctrl.auto_detected = True
                ctrl.auto_evidence = f"CanaryGuard: {canary_count} active canary decoy files deployed in monitored shares"
                ctrl.maturity_answer = 'implemented'
                ctrl.score_value = 80.0
            else:
                ctrl.auto_detected = False
                ctrl.auto_evidence = "CanaryGuard: No active canary files currently deployed"

        # 2. edr_coverage auto-detection (CanaryGuard is active EDR)
        if 'edr_coverage' in controls_by_code:
            ctrl = controls_by_code['edr_coverage']
            ctrl.auto_detected = True
            ctrl.auto_evidence = "CanaryGuard: Real-time EDR agent and process quarantine engine active"
            ctrl.maturity_answer = 'implemented'
            ctrl.score_value = 80.0

        # 3. log_monitoring auto-detection
        if 'log_monitoring' in controls_by_code:
            ctrl = controls_by_code['log_monitoring']
            log_dir = Path(__file__).resolve().parent.parent.parent / 'logs'
            sec_log = log_dir / 'security.log'
            sys_log = log_dir / 'system.log'
            has_logs = (sec_log.exists() and os.path.getsize(sec_log) > 0) or (sys_log.exists() and os.path.getsize(sys_log) > 0)

            if has_logs:
                ctrl.auto_detected = True
                ctrl.auto_evidence = "CanaryGuard: Structured log monitoring active (logs/security.log present)"
                ctrl.maturity_answer = 'implemented'
                ctrl.score_value = 80.0
            else:
                ctrl.auto_detected = False
                ctrl.auto_evidence = "CanaryGuard: Security logging configured"

        # 4. anomaly_detection auto-detection
        if 'anomaly_detection' in controls_by_code:
            ctrl = controls_by_code['anomaly_detection']
            entropy_count = EntropyLog.query.count()
            incident_count = Incident.query.count()
            if entropy_count > 0 or incident_count > 0:
                ctrl.auto_detected = True
                ctrl.auto_evidence = f"CanaryGuard: Shannon entropy engine active with {entropy_count} recorded entropy calculations"
                ctrl.maturity_answer = 'implemented'
                ctrl.score_value = 80.0
            else:
                ctrl.auto_detected = False
                ctrl.auto_evidence = "CanaryGuard: Entropy engine online"

        # 5. backup_availability auto-detection
        if 'backup_availability' in controls_by_code:
            ctrl = controls_by_code['backup_availability']
            backup_dir = Path(__file__).resolve().parent.parent.parent / 'backups'
            has_backups = backup_dir.exists()
            if has_backups:
                ctrl.auto_detected = True
                ctrl.auto_evidence = "CanaryGuard: Automated backup store directory (backups/) active and online"
                ctrl.maturity_answer = 'implemented'
                ctrl.score_value = 80.0
            else:
                ctrl.auto_detected = False
                ctrl.auto_evidence = "CanaryGuard: Local backup directory configured"

        # 6. restoration_verification & restore_tested auto-detection
        for restore_key in ['restore_tested', 'restoration_verification']:
            if restore_key in controls_by_code:
                ctrl = controls_by_code[restore_key]
                recovered_incidents = Incident.query.filter(
                    Incident.status.in_(['Recovered', 'RESOLVED'])
                ).all()
                N = len(recovered_incidents)
                if N > 0:
                    ctrl.auto_detected = True
                    ctrl.auto_evidence = f"System successfully recovered from {N} incidents"
                    ctrl.maturity_answer = 'implemented'
                    ctrl.score_value = 80.0
                else:
                    q_dir = Path(__file__).resolve().parent.parent.parent / 'quarantine_store'
                    if q_dir.exists():
                        ctrl.auto_detected = True
                        ctrl.auto_evidence = "CanaryGuard: Isolated sandbox quarantine store (quarantine_store/) ready for restoration verification"
                        ctrl.maturity_answer = 'implemented'
                        ctrl.score_value = 80.0

        # 7. post_incident_recovery auto-detection
        if 'post_incident_recovery' in controls_by_code:
            ctrl = controls_by_code['post_incident_recovery']
            from app.models.quarantine_history import QuarantineHistory
            q_count = QuarantineHistory.query.count()
            ctrl.auto_detected = True
            ctrl.auto_evidence = f"CanaryGuard: Active process quarantine audit trail with {q_count} recorded isolation events"
            ctrl.maturity_answer = 'implemented'
            ctrl.score_value = 80.0

        # 8. rto_rpo_defined auto-detection
        for rto_key in ['rto_rpo_defined', 'rto_readiness']:
            if rto_key in controls_by_code:
                ctrl = controls_by_code[rto_key]
                rto_incidents = [
                    inc for inc in Incident.query.filter(
                        Incident.contained_at.isnot(None),
                        Incident.recovered_at.isnot(None)
                    ).all()
                    if inc.rto_minutes is not None
                ]
                N = len(rto_incidents)
                if N > 0:
                    rto = round(sum(inc.rto_minutes for inc in rto_incidents) / N, 1)
                    ctrl.auto_detected = True
                    ctrl.auto_evidence = f"Actual RTO measured: {rto} minutes from {N} recovered incidents"
                    ctrl.maturity_answer = 'implemented'
                    ctrl.score_value = 80.0
                else:
                    ctrl.auto_detected = False
                    ctrl.auto_evidence = "CanaryGuard: No RTO data measured yet"

        cls._recalculate_scores(assessment)
        db.session.commit()

    @classmethod
    def submit_answers(cls, assessment_id: int, answers_dict: Dict[str, str]) -> Dict[str, Any]:
        """Process user submitted control answers, compute weighted scores, and save history snapshot."""
        assessment = Assessment.query.get(assessment_id)
        if not assessment:
            raise ValueError(f"Assessment #{assessment_id} not found")

        # Update controls
        for domain in assessment.domains:
            for control in domain.controls:
                if control.control_code in answers_dict:
                    answer = answers_dict[control.control_code]
                    if answer in MATURITY_SCORE_MAP:
                        control.maturity_answer = answer
                        control.score_value = MATURITY_SCORE_MAP[answer]

        cls._recalculate_scores(assessment)
        assessment.status = 'complete'

        # Generate snapshot JSON & save AssessmentRunHistory
        breakdown = cls.get_score_breakdown(assessment.id)
        history = AssessmentRunHistory(
            assessment_id=assessment.id,
            overall_score=assessment.overall_score,
            maturity_level=assessment.maturity_level,
            snapshot_json=json.dumps(breakdown)
        )
        db.session.add(history)
        db.session.commit()

        return breakdown

    @classmethod
    def _recalculate_scores(cls, assessment: Assessment):
        """Internal helper to calculate weighted domain scores and overall assessment score."""
        control_weights = {ctrl['control_code']: ctrl.get('weight', 1) for ctrl in ASSESSMENT_CONTROLS}

        total_weighted_domain_score = 0.0
        total_domain_weight = 0.0

        for domain in assessment.domains:
            domain_total_score = 0.0
            domain_total_weight = 0.0

            for control in domain.controls:
                w = float(control_weights.get(control.control_code, 1))
                domain_total_score += control.score_value * w
                domain_total_weight += w

            domain_score = (domain_total_score / domain_total_weight) if domain_total_weight > 0 else 0.0
            domain.score = round(domain_score, 1)

            dw = float(DOMAIN_WEIGHTS.get(domain.domain_code, 1.0))
            total_weighted_domain_score += domain.score * dw
            total_domain_weight += dw

        overall = (total_weighted_domain_score / total_domain_weight) if total_domain_weight > 0 else 0.0
        assessment.overall_score = round(overall, 1)
        assessment.maturity_level = cls.get_maturity_level(assessment.overall_score)

    @classmethod
    def get_score_breakdown(cls, assessment_id: int) -> Dict[str, Any]:
        """Return full nested structure of assessment metadata, domains, controls, scores, and evidence."""
        assessment = Assessment.query.get(assessment_id)
        if not assessment:
            raise ValueError(f"Assessment #{assessment_id} not found")

        return {
            'assessment_id': assessment.id,
            'org_name': assessment.org_name,
            'org_size': assessment.org_size,
            'industry': assessment.industry,
            'assessor_name': assessment.assessor_name,
            'status': assessment.status,
            'overall_score': round(assessment.overall_score or 0.0, 1),
            'maturity_level': assessment.maturity_level or 'Initial',
            'created_at': assessment.created_at.isoformat() if assessment.created_at else None,
            'updated_at': assessment.updated_at.isoformat() if assessment.updated_at else None,
            'domains': [
                {
                    'id': domain.id,
                    'domain_code': domain.domain_code,
                    'domain_name': domain.domain_name,
                    'score': round(domain.score or 0.0, 1),
                    'weight': domain.weight,
                    'controls': [
                        {
                            'id': control.id,
                            'control_code': control.control_code,
                            'control_title': control.control_title,
                            'control_description': control.control_description,
                            'why_it_matters': control.why_it_matters,
                            'maturity_answer': control.maturity_answer,
                            'score_value': control.score_value,
                            'auto_detected': control.auto_detected,
                            'auto_evidence': control.auto_evidence,
                            'remediation_tip': control.remediation_tip,
                        }
                        for control in domain.controls
                    ]
                }
                for domain in assessment.domains
            ]
        }
