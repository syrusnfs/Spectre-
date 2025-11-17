"""
Application Factory
Creates and configures the Flask application
"""
import os
from datetime import datetime
from flask import Flask, render_template
from app.config import config
from app.extensions import db, init_extensions


def create_app(config_name=None):
    """
    Application factory pattern
    Creates and configures the Flask application instance

    Args:
        config_name: Configuration name ('development', 'production', 'testing')
                    If None, uses FLASK_ENV environment variable

    Returns:
        Flask application instance
    """
    # Determine configuration
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'production')

    # Create Flask app
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')

    # Load configuration
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    # Initialize extensions
    init_extensions(app)

    # Register blueprints
    from app.routes import register_blueprints
    register_blueprints(app)

    # Register error handlers
    register_error_handlers(app)

    # Register security headers
    register_security_headers(app)

    # Register Jinja context processors
    register_context_processors(app)

    # Initialize scheduler (only in main process, not in reloader)
    if os.getenv('WERKZEUG_RUN_MAIN') == 'true' or not app.debug:
        from app.services.scheduler_service import init_scheduler
        scheduler = init_scheduler(app)

        # Inject scheduler into routines blueprint
        from app.routes.routines import init_routines_blueprint
        init_routines_blueprint(scheduler, app)

        # Store scheduler in app config for access
        app.config['SCHEDULER'] = scheduler

    return app


def register_error_handlers(app):
    """Register custom error handlers"""

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('error.html',
                             error_title='Access Denied',
                             error_message='You do not have permission to access this resource.',
                             error_icon='lock-fill'), 403

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('error.html',
                             error_title='Page Not Found',
                             error_message='The page you are looking for does not exist or has been moved.',
                             error_icon='search'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('error.html',
                             error_title='Internal Error',
                             error_message='A server error occurred. Please try again later.',
                             error_icon='exclamation-triangle-fill'), 500

    @app.errorhandler(Exception)
    def handle_exception(e):
        # Log exception
        app.logger.error(f'Unhandled exception: {str(e)}')

        # Show generic error in production
        if not app.debug:
            return render_template('error.html',
                                 error_title='Unexpected Error',
                                 error_message='An unexpected error occurred. Please contact the administrator.',
                                 error_icon='exclamation-circle-fill'), 500
        # In development, let Flask show the error
        raise e


def register_security_headers(app):
    """Register security headers middleware"""

    @app.after_request
    def set_security_headers(response):
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'

        # HSTS - Force HTTPS (only if not development)
        if not app.debug:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com; "
            "script-src-elem 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "style-src-elem 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "connect-src 'self' https://cdn.jsdelivr.net; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        # Permissions Policy (substituir Feature-Policy deprecated)
        response.headers['Permissions-Policy'] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )

        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Remove headers that expose server information
        response.headers.pop('Server', None)
        response.headers.pop('X-Powered-By', None)

        return response


def register_context_processors(app):
    """Register Jinja2 context processors"""

    @app.context_processor
    def inject_now():
        """Inject datetime.now() into Jinja templates"""
        return {'now': datetime.now}
