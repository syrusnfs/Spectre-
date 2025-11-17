"""
Blueprint routes registration
"""


def register_blueprints(app):
    """Register all application blueprints"""

    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.users import users_bp
    from app.routes.servers import servers_bp
    from app.routes.routines import routines_bp
    from app.routes.backups import backups_bp
    from app.routes.logs import logs_bp
    from app.routes.profile import profile_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(servers_bp)
    app.register_blueprint(routines_bp)
    app.register_blueprint(backups_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(profile_bp)
