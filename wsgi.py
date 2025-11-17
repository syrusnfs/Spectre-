"""
WSGI Entry Point for Gunicorn
Production-ready entry point for the Spectre application

Usage:
    gunicorn -c gunicorn.conf.py wsgi:app
    gunicorn --workers 4 --bind 0.0.0.0:5000 wsgi:app
"""
import os
from app import create_app
from app.extensions import db

# Create application instance
app = create_app()


def init_database():
    """Initialize database tables"""
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✓ Database tables created")


# Initialize database on startup
if __name__ != '__main__':
    # Running under Gunicorn
    init_database()
    print("\n" + "="*60)
    print("  SPECTRE - Automated Backup System")
    print("  Running with Gunicorn")
    print("="*60 + "\n")


# For development server (not recommended for production)
if __name__ == '__main__':
    init_database()

    print("\n" + "="*60)
    print("  SPECTRE - Automated Backup System")
    print("  ⚠ Development Server (Use Gunicorn for production)")
    print("="*60 + "\n")

    # Get settings from environment
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', '5000'))

    app.run(debug=debug_mode, host=host, port=port, use_reloader=False)
