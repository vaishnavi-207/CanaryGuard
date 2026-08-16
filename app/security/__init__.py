"""
Security and authentication package for CanaryGuard EDR.
Contains authentication decorators and security context helpers.
"""

from functools import wraps
from flask import session, request, redirect, url_for, jsonify, current_app


def login_required(f):
    """
    Decorator requiring active session authentication for protected routes.
    Returns JSON 401 error response for API endpoints and redirects to login for HTML pages.
    Bypasses check only when TESTING config flag is active.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_app.config.get('TESTING') and not session.get('user_id'):
            return f(*args, **kwargs)

        if not session.get('user_id'):
            if request.path.startswith('/api') or request.is_json:
                return jsonify({
                    'error': 'Unauthorized',
                    'message': 'Authentication required. Please log in.'
                }), 401
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function
