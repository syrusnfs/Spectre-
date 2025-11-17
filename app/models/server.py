"""
Server model
"""
from datetime import datetime
from app.extensions import db


class Server(db.Model):
    """Server model with encrypted credentials"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, default=22)
    username = db.Column(db.String(100), nullable=False)
    auth_type = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(255), nullable=True)
    ssh_key = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    routines = db.relationship('BackupRoutine', backref='server', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Server {self.name} ({self.host}:{self.port})>'
