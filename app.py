from flask import Flask, redirect, url_for
from config import Config
from models.database import db

# Import blueprints
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.api import api_bp


def create_app():
    """Application factory"""
    app = Flask(__name__)
    
    # Load configuration
    app.config['SECRET_KEY'] = Config.SECRET_KEY
    app.config['ENV'] = Config.ENV
    app.config['DEBUG'] = Config.DEBUG
    
    # Initialize database
    db.init_db()
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp)
    
    # Root route
    @app.route('/')
    def index():
        """Root redirect"""
        from flask import session
        if session.get("user") == Config.ADMIN_USERNAME:
            if Config.are_api_keys_configured():
                return redirect(url_for('dashboard.index'))
            else:
                return redirect(url_for('auth.setup'))
        return redirect(url_for('auth.login'))
    
    return app


if __name__ == '__main__':
    app = create_app()
    print(f"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║          ThreatIntel Processor Pro - Starting...              ║   ║                                                               ║
    ║  Developed & Designed by: Infotech Teams                      ║
    ║  Server: http://{Config.HOST}:{Config.PORT}                   ║
    ║  Environment: {Config.ENV}                                    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Check if API keys are configured
    if not Config.are_api_keys_configured():
        print("\n⚠️  WARNING: API keys not configured!")
        print("   Please configure your API keys after logging in.\n")
    else:
        print("\n✓ API keys are configured")
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    )