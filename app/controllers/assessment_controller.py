from flask import jsonify, request, render_template
from app.services.assessment_service import AssessmentService
from app.logging.logger import get_system_logger

logger = get_system_logger()


class AssessmentController:

    @staticmethod
    def assessment_page():
        return render_template('readiness_assessment.html', page_title='Ransomware Readiness Assessment')

    @staticmethod
    def new_assessment():
        try:
            data = request.get_json() or {}
            org_name = data.get('org_name', '').strip()
            org_size = data.get('org_size', '').strip()
            industry = data.get('industry', '').strip()
            assessor_name = data.get('assessor_name', '').strip()
            if not org_name or not org_size or not industry or not assessor_name:
                return jsonify({'error': 'All fields are required.'}), 400
            assessment_id = AssessmentService.create_assessment(org_name, org_size, industry, assessor_name)
            AssessmentService.auto_detect_controls(assessment_id)
            breakdown = AssessmentService.get_score_breakdown(assessment_id)
            return jsonify({'assessment_id': assessment_id, 'domains': breakdown['domains']}), 201
        except Exception as e:
            logger.error(f'Error creating assessment: {e}')
            return jsonify({'error': 'Failed to create assessment.'}), 500

    @staticmethod
    def submit_assessment(assessment_id):
        try:
            data = request.get_json() or {}
            answers = data.get('answers', {})
            if not answers:
                return jsonify({'error': 'No answers provided.'}), 400
            result = AssessmentService.submit_answers(assessment_id, answers)
            return jsonify(result), 200
        except Exception as e:
            logger.error(f'Error submitting assessment: {e}')
            return jsonify({'error': 'Failed to submit assessment.'}), 500

    @staticmethod
    def score_breakdown(assessment_id):
        try:
            breakdown = AssessmentService.get_score_breakdown(assessment_id)
            return jsonify(breakdown), 200
        except Exception as e:
            logger.error(f'Error getting score breakdown: {e}')
            return jsonify({'error': 'Failed to get breakdown.'}), 500

    @staticmethod
    def assessment_history():
        try:
            from app.models.assessment import Assessment
            assessments = Assessment.query.filter_by(status='complete').order_by(Assessment.created_at.desc()).all()
            history = [{
                'id': a.id,
                'org_name': a.org_name,
                'overall_score': a.overall_score,
                'maturity_level': a.maturity_level,
                'created_at': a.created_at.strftime('%Y-%m-%d %H:%M') if a.created_at else 'N/A'
            } for a in assessments]
            return jsonify(history), 200
        except Exception as e:
            logger.error(f'Error getting history: {e}')
            return jsonify({'error': 'Failed to get history.'}), 500

    @staticmethod
    def download_report(assessment_id):
        try:
            from flask import send_file
            from app.services.pdf_service import PDFService
            pdf_buffer = PDFService.generate_readiness_report(assessment_id)
            return send_file(
                pdf_buffer,
                as_attachment=True,
                download_name=f"CanaryGuard_Readiness_Assessment_Report_{assessment_id}.pdf",
                mimetype='application/pdf'
            )
        except Exception as e:
            logger.error(f'Error generating readiness report for assessment #{assessment_id}: {e}')
            return jsonify({'error': 'Failed to generate readiness PDF report.'}), 500

