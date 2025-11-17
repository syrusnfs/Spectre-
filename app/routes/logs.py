"""
Backup log routes
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from app.extensions import db
from app.models import BackupLog, BackupRoutine
from app.security import admin_required, require_otp_verification, sanitize_error_message

logs_bp = Blueprint('logs', __name__, url_prefix='/logs')


@logs_bp.route('/')
@login_required
def logs():
    # Admin sees all logs, User sees only their own
    if current_user.is_admin():
        logs = BackupLog.query.order_by(BackupLog.timestamp.desc()).all()
    else:
        logs = BackupLog.query.join(BackupRoutine).filter(
            BackupRoutine.user_id == current_user.id
        ).order_by(BackupLog.timestamp.desc()).all()

    return render_template('logs.html', logs=logs)


@logs_bp.route('/clear', methods=['POST'])
@login_required
@admin_required
def clear_logs():
    # Verify OTP before proceeding
    if not require_otp_verification():
        return redirect(url_for('logs.logs'))

    try:
        # Admin can delete ALL system logs
        BackupLog.query.delete()
        db.session.commit()

        # Audit log
        current_app.logger.info(f'[AUDIT] All system logs were deleted by admin {current_user.username}')

        flash('All system logs have been successfully deleted!', 'success')
    except Exception as e:
        db.session.rollback()
        safe_msg = sanitize_error_message(e, "Error deleting logs")
        flash(safe_msg, 'danger')

    return redirect(url_for('logs.logs'))
