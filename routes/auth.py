from flask import Blueprint, request, session, redirect, url_for, render_template, flash
from functools import wraps
from config import Config

auth_bp = Blueprint('auth', __name__)


def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user") != Config.ADMIN_USERNAME:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


def api_keys_required(f):
    """Decorator to require API keys to be configured"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not Config.are_api_keys_configured():
            return redirect(url_for('auth.setup'))
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and handler"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if username == Config.ADMIN_USERNAME and password == Config.ADMIN_PASSWORD:
            session['user'] = Config.ADMIN_USERNAME
            
            # Check if API keys are configured
            if not Config.are_api_keys_configured():
                return redirect(url_for('auth.setup'))
            
            return redirect(url_for('dashboard.index'))
        
        flash('Invalid credentials', 'error')
        return render_template('login.html')
    
    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    """Logout handler"""
    session.pop('user', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/setup', methods=['GET', 'POST'])
@login_required
def setup():
    """API keys setup page"""
    if request.method == 'POST':
        otx_key = request.form.get('otx_api_key', '').strip()
        abuseipdb_key = request.form.get('abuseipdb_api_key', '').strip()
        
        if not otx_key or not abuseipdb_key:
            flash('Both API keys are required', 'error')
            return render_template('setup.html')
        
        # Save API keys
        if Config.save_api_keys(otx_key, abuseipdb_key):
            flash('API keys saved successfully!', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            flash('Error saving API keys. Please try again.', 'error')
    
    # Load current keys if they exist
    current_keys = Config.get_api_keys()
    return render_template('setup.html', keys=current_keys)