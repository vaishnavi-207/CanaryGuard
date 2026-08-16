from datetime import datetime, timezone
from flask import Blueprint, request, render_template, redirect, url_for, session, jsonify, flash
from app.database.db import db
from app.models.user import User

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False
    from werkzeug.security import generate_password_hash, check_password_hash

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


def verify_password(password: str, password_hash: str) -> bool:
    if not password or not password_hash:
        return False
    try:
        from werkzeug.security import check_password_hash
        if password_hash.startswith('scrypt:') or password_hash.startswith('pbkdf2:'):
            return check_password_hash(password_hash, password)
        if HAS_BCRYPT and password_hash.startswith('$2'):
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        from werkzeug.security import check_password_hash
        return check_password_hash(password_hash, password)
    except Exception:
        return False


def hash_password(password: str) -> str:
    """Generate password hash (supports bcrypt with werkzeug fallback)."""
    if HAS_BCRYPT:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return generate_password_hash(password)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user authentication login."""
    if request.method == 'GET':
        if session.get('user_id'):
            return redirect(url_for('main.dashboard'))
        return render_template('login.html')

    # POST request processing
    if request.is_json:
        data = request.get_json() or {}
        username = data.get('username', '').strip()
        password = data.get('password', '')
    else:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

    if not username or not password:
        err_msg = 'Username and password are required.'
        if request.is_json:
            return jsonify({'error': err_msg}), 400
        return render_template('login.html', error=err_msg)

    user = User.query.filter_by(username=username).first()

    if user and user.is_active and verify_password(password, user.password_hash):
        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role

        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        next_page = request.args.get('next') or url_for('main.dashboard')

        if request.is_json:
            return jsonify({
                'message': 'Login successful',
                'redirect': next_page,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'role': user.role
                }
            }), 200

        return redirect(next_page)

    err_msg = 'Invalid username or password.'
    if request.is_json:
        return jsonify({'error': err_msg}), 401
    return render_template('login.html', error=err_msg)


@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """Handle user session logout."""
    session.clear()
    if request.is_json:
        return jsonify({'message': 'Logged out successfully'}), 200
    return redirect(url_for('auth.login'))
