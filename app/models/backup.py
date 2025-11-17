"""
Backup-related models
"""
from datetime import datetime
from app.extensions import db


class BackupRoutine(db.Model):
    """Backup routine configuration"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    remote_path = db.Column(db.String(500), nullable=False)
    local_path = db.Column(db.String(500), nullable=False)
    schedule_type = db.Column(db.String(20), nullable=False)
    schedule_time = db.Column(db.String(10), nullable=True)
    retention_days = db.Column(db.Integer, default=30)
    enabled = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_run = db.Column(db.DateTime, nullable=True)

    # Relationships
    executions = db.relationship('BackupExecution', backref='routine', lazy=True, cascade='all, delete-orphan')
    logs = db.relationship('BackupLog', backref='routine', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<BackupRoutine {self.name}>'


class BackupExecution(db.Model):
    """Backup execution record"""

    id = db.Column(db.Integer, primary_key=True)
    routine_id = db.Column(db.Integer, db.ForeignKey('backup_routine.id'), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), nullable=False)
    files_count = db.Column(db.Integer, default=0)
    total_size = db.Column(db.BigInteger, default=0)
    error_message = db.Column(db.Text, nullable=True)
    backup_path = db.Column(db.String(500), nullable=True)

    def __repr__(self):
        return f'<BackupExecution {self.id} ({self.status})>'


class BackupLog(db.Model):
    """Backup log entry"""

    id = db.Column(db.Integer, primary_key=True)
    routine_id = db.Column(db.Integer, db.ForeignKey('backup_routine.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    level = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<BackupLog {self.level}: {self.message[:50]}>'
