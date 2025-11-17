"""
Main/Dashboard routes
"""
import shutil
from flask import Blueprint, render_template, current_app
from flask_login import login_required, current_user
from app.models import Server, BackupRoutine, BackupExecution, BackupLog

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
@login_required
def index():
    total_servers = Server.query.filter_by(user_id=current_user.id).count()
    total_routines = BackupRoutine.query.filter_by(user_id=current_user.id).count()
    total_backups = BackupExecution.query.join(BackupRoutine).filter(BackupRoutine.user_id == current_user.id).count()
    recent_logs = BackupLog.query.join(BackupRoutine).filter(BackupRoutine.user_id == current_user.id).order_by(BackupLog.timestamp.desc()).limit(5).all()

    # Obter informação de espaço em disco do diretório de backups
    import os
    backup_path = os.getenv('BACKUP_BASE_PATH', '/opt/backups')

    try:
        # Usar o diretório de backups configurado no .env
        disk_usage = shutil.disk_usage(backup_path)
        disk_total = disk_usage.total / (1024 ** 3)  # GB
        disk_used = disk_usage.used / (1024 ** 3)    # GB
        disk_free = disk_usage.free / (1024 ** 3)    # GB
        disk_percent = (disk_used / disk_total) * 100
    except:
        disk_total = disk_used = disk_free = disk_percent = 0

    return render_template('index.html',
                         total_servers=total_servers,
                         total_routines=total_routines,
                         total_backups=total_backups,
                         recent_logs=recent_logs,
                         disk_total=disk_total,
                         disk_used=disk_used,
                         disk_free=disk_free,
                         disk_percent=disk_percent)
