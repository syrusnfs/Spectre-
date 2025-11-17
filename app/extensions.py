"""
Flask extensions initialization
Singleton instances shared across the application
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Initialize extensions (without app binding)
db = SQLAlchemy()
login_manager = LoginManager()


def init_extensions(app):
    """Initialize Flask extensions with app context"""

    # Initialize database
    db.init_app(app)

    # Initialize login manager
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = None

    # Import and register user loader
    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
