from flask import Blueprint, render_template
from app.controllers.assessment_controller import AssessmentController
from app.security import login_required

assessment_bp = Blueprint('assessment', __name__)

# UI Route
assessment_bp.route('/readiness-assessment', methods=['GET'])(login_required(AssessmentController.assessment_page))

# API Routes
assessment_bp.route('/api/assessment/new', methods=['POST'])(login_required(AssessmentController.new_assessment))
assessment_bp.route('/api/assessment/<int:assessment_id>/submit', methods=['POST'])(login_required(AssessmentController.submit_assessment))
assessment_bp.route('/api/assessment/<int:assessment_id>/score-breakdown', methods=['GET'])(login_required(AssessmentController.score_breakdown))
assessment_bp.route('/api/assessment/history', methods=['GET'])(login_required(AssessmentController.assessment_history))
assessment_bp.route('/api/assessment/<int:assessment_id>/report', methods=['GET'])(login_required(AssessmentController.download_report))
