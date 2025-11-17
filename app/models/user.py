"""
User model
"""
from datetime import datetime
from flask_login import UserMixin
from app.extensions import db


class User(UserMixin, db.Model):
    """User model with authentication and backup credentials"""

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    backup_password = db.Column(db.String(255), nullable=False)  # Encrypted password for user backups
    role = db.Column(db.String(20), nullable=False, default='user')  # 'admin' or 'user'
    otp_secret = db.Column(db.String(32), nullable=True)
    otp_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    servers = db.relationship('Server', backref='user', lazy=True, cascade='all, delete-orphan')
    routines = db.relationship('BackupRoutine', backref='user', lazy=True, cascade='all, delete-orphan')

    def is_admin(self):
        """Checks if the user has admin role"""
        return self.role == 'admin'

    def __repr__(self):
        return f'<User {self.username}>'
