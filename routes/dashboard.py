"""
Dashboard Routes Module
Main dashboard interface and related views
Developed & Designed by Dip Kar
"""

from flask import Blueprint, render_template, session
from datetime import datetime
from models.database import db
from routes.auth import login_required, api_keys_required

# Create dashboard blueprint
dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard')
@login_required
@api_keys_required
def index():
    """
    Main dashboard page
    
    Displays:
    - IP lookup interface
    - Threat overview charts
    - Top malicious IPs
    - Geographic threat map
    - Export options
    
    Requires:
    - User must be logged in
    - API keys must be configured
    """
    # Get current statistics
    total_records = db.get_ioc_count()
    current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    
    # Render dashboard template
    return render_template(
        'dashboard.html',
        total_records=total_records,
        current_time=current_time
    )


@dashboard_bp.route('/stats')
@login_required
@api_keys_required
def stats():
    """
    Statistics page (optional - can be expanded)
    
    Shows detailed database statistics
    """
    stats_data = db.get_database_stats()
    recent_checks = db.get_recent_checks(limit=50)
    
    return render_template(
        'stats.html',
        stats=stats_data,
        recent_checks=recent_checks
    )


@dashboard_bp.route('/history')
@login_required
@api_keys_required
def history():
    """
    Check history page (optional - can be expanded)
    
    Shows history of all IP checks
    """
    checks = db.get_recent_checks(limit=100)
    
    return render_template(
        'history.html',
        checks=checks
    )