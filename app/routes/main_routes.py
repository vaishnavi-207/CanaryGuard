from flask import Blueprint, render_template, current_app
from app.models.incident import Incident
from app.models.canary_file import CanaryFile
from app.models.quarantine_history import QuarantineHistory
from app.models.monitored_folder import MonitoredFolder
from app.models.system_setting import SystemSetting
from app.services.process_service import ProcessService
from app.security import login_required

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
@login_required
def dashboard():
    monitor_mgr = getattr(current_app, 'monitor_manager', None)
    status = monitor_mgr.get_status() if monitor_mgr else {'is_running': False, 'monitored_paths': []}

    total_incidents = Incident.query.count()
    active_incidents = Incident.query.filter_by(status='ACTIVE').limit(10).all()
    canary_count = CanaryFile.query.filter_by(is_active=True).count()
    quarantine_count = QuarantineHistory.query.count()

    return render_template(
        'dashboard.html',
        status=status,
        total_incidents=total_incidents,
        active_incidents=active_incidents,
        canary_count=canary_count,
        quarantine_count=quarantine_count,
        page_title="Executive SOC Overview"
    )


@main_bp.route('/threat-feed')
@login_required
def threat_feed():
    incidents = Incident.query.order_by(Incident.created_at.desc()).limit(50).all()
    return render_template('threat_feed.html', incidents=incidents, page_title="Live Threat Feed")


@main_bp.route('/incidents')
@login_required
def incidents_view():
    incidents = Incident.query.order_by(Incident.created_at.desc()).limit(50).all()
    return render_template('incidents.html', incidents=incidents, page_title="Incident Management")


@main_bp.route('/incidents/<int:incident_id>')
@login_required
def incident_detail_view(incident_id):
    from flask import abort
    from app.services.ai_service import AIService
    incident = Incident.query.get(incident_id)
    if not incident:
        abort(404)

    explanation = AIService.generate_explanation(incident)
    recommendations = AIService.get_recommendations(incident)
    summary = AIService.generate_incident_summary(incident)
    timeline = AIService.generate_timeline(incident)
    score = int(incident.confidence_score) if incident.confidence_score else AIService.calculate_threat_score({
        'canary_triggered': incident.canary_triggered,
        'entropy_value': incident.entropy_value,
        'process_name': incident.process_name,
        'description': incident.description
    })

    return render_template(
        'incident_detail.html',
        incident=incident,
        explanation=explanation,
        recommendations=recommendations,
        summary=summary,
        timeline=timeline,
        score=score,
        page_title=f"Incident #{incident.id} AI Threat Analysis"
    )


@main_bp.route('/processes')
@login_required
def processes_view():
    processes = ProcessService.list_active_processes()
    quarantined = QuarantineHistory.query.order_by(QuarantineHistory.created_at.desc()).limit(20).all()
    return render_template('processes.html', processes=processes, quarantined=quarantined, page_title="Process Explorer & Quarantine")


@main_bp.route('/canaries')
@login_required
def canaries_view():
    canaries = CanaryFile.query.order_by(CanaryFile.created_at.desc()).limit(50).all()
    return render_template('canaries.html', canaries=canaries, page_title="Canary File Management")


@main_bp.route('/monitored-folders')
@login_required
def folders_view():
    folders = MonitoredFolder.query.order_by(MonitoredFolder.created_at.desc()).limit(50).all()
    return render_template('monitored_folders.html', folders=folders, page_title="Monitored Folders")


@main_bp.route('/statistics')
@login_required
def statistics_view():
    incidents = Incident.query.limit(50).all()
    return render_template('statistics.html', incidents=incidents, page_title="Threat Statistics & Analytics")


@main_bp.route('/settings')
@login_required
def settings_view():
    settings = SystemSetting.query.limit(50).all()
    return render_template('settings.html', settings=settings, page_title="System Configuration")


@main_bp.route('/logs')
@login_required
def logs_view():
    return render_template('logs.html', page_title="System & Security Log Viewer")


@main_bp.route('/about')
@login_required
def about_view():
    return render_template('about.html', page_title="About CanaryGuard EDR")
