"""
Backup execution management routes
"""
import os
import shutil
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app
from flask_login import login_required, current_user
from app.extensions import db
from app.models import BackupExecution, BackupRoutine
from app.security import require_otp_verification, sanitize_error_message
from app.services.backup_service import restore_backup_to_server

backups_bp = Blueprint('backups', __name__, url_prefix='/backups')


@backups_bp.route('/')
@login_required
def backups():
    # Admin sees all backups, User only sees their own
    if current_user.is_admin():
        backups = BackupExecution.query.order_by(BackupExecution.start_time.desc()).all()
    else:
        backups = BackupExecution.query.join(BackupRoutine).filter(
            BackupRoutine.user_id == current_user.id
        ).order_by(BackupExecution.start_time.desc()).all()

    return render_template('backups.html', backups=backups)


@backups_bp.route('/download/<int:id>')
@login_required
def download_backup(id):
    """Allows downloading an individual backup"""
    backup = BackupExecution.query.get_or_404(id)

    # IDOR Protection: Admin can download any backup, User only their own
    if not current_user.is_admin() and backup.routine.user_id != current_user.id:
        current_app.logger.warning(f'[AUDIT] Unauthorized download attempt of backup ID {id} by user {current_user.username}')
        flash('Access denied', 'danger')
        return redirect(url_for('backups.backups'))

    # Check if path is defined
    if not backup.backup_path:
        flash('Backup path not defined', 'danger')
        return redirect(url_for('backups.backups'))

    try:
        # PREVENT RACE CONDITION: Use send_file directly with try/except
        # send_file performs atomic verification
        filename = os.path.basename(backup.backup_path)

        return send_file(
            backup.backup_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/gzip'
        )
    except FileNotFoundError:
        flash('Backup file not found', 'danger')
        return redirect(url_for('backups.backups'))
    except PermissionError:
        flash('No permissions to access the file', 'danger')
        return redirect(url_for('backups.backups'))
    except Exception as e:
        current_app.logger.error(f'Error during download: {str(e)}')
        flash('Error downloading backup', 'danger')
        return redirect(url_for('backups.backups'))


@backups_bp.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_backup(id):
    # Verify OTP before proceeding
    if not require_otp_verification():
        return redirect(url_for('backups.backups'))

    backup = BackupExecution.query.get_or_404(id)

    # IDOR Protection: Admin can delete any backup, User only their own
    if not current_user.is_admin() and backup.routine.user_id != current_user.id:
        current_app.logger.warning(f'[AUDIT] Unauthorized deletion attempt of backup ID {id} by user {current_user.username}')
        flash('Access denied', 'danger')
        return redirect(url_for('backups.backups'))

    try:
        # Delete the backup file if it exists
        if backup.backup_path and os.path.exists(backup.backup_path):
            if os.path.isfile(backup.backup_path):
                # If it's a file (tar.gz), remove file
                os.remove(backup.backup_path)
            elif os.path.isdir(backup.backup_path):
                # If it's a directory (old backups), remove directory
                shutil.rmtree(backup.backup_path)

        # Delete the database record
        db.session.delete(backup)
        db.session.commit()

        flash('Backup deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        safe_msg = sanitize_error_message(e, "Error deleting backup")
        flash(safe_msg, 'danger')

    return redirect(url_for('backups.backups'))


@backups_bp.route('/restore/<int:id>', methods=['POST'])
@login_required
def restore_backup(id):
    """Restores a backup to the original server"""
    backup = BackupExecution.query.get_or_404(id)

    # IDOR Protection: Admin can restore any backup, User only their own
    if not current_user.is_admin() and backup.routine.user_id != current_user.id:
        current_app.logger.warning(f'[AUDIT] Unauthorized restore attempt of backup ID {id} by user {current_user.username}')
        flash('Access denied', 'danger')
        return redirect(url_for('backups.backups'))

    # Check if the backup was successful
    if backup.status != 'success' or not backup.backup_path:
        flash('This backup cannot be restored (invalid status or path not found)', 'danger')
        return redirect(url_for('backups.backups'))

    # Check if the file exists
    if not os.path.exists(backup.backup_path):
        flash('Backup file not found in the system', 'danger')
        return redirect(url_for('backups.backups'))

    try:
        # Execute restore
        success, message = restore_backup_to_server(backup)

        if success:
            flash(message, 'success')
        else:
            flash(message, 'danger')

    except Exception as e:
        safe_msg = sanitize_error_message(e, "Error restoring backup")
        flash(safe_msg, 'danger')

    return redirect(url_for('backups.backups'))


@backups_bp.route('/clear', methods=['POST'])
@login_required
def clear_backups():
    # Verify OTP before proceeding
    if not require_otp_verification():
        return redirect(url_for('backups.backups'))

    try:
        # Get all backups from the user's routines
        backups = BackupExecution.query.join(BackupRoutine).filter(
            BackupRoutine.user_id == current_user.id
        ).all()

        # Delete the physical files (files or directories)
        for backup in backups:
            if backup.backup_path and os.path.exists(backup.backup_path):
                try:
                    if os.path.isfile(backup.backup_path):
                        os.remove(backup.backup_path)
                    elif os.path.isdir(backup.backup_path):
                        shutil.rmtree(backup.backup_path)
                except Exception as e:
                    print(f"Error deleting backup files {backup.id}: {str(e)}")

        # Delete the database records
        backup_ids = [b.id for b in backups]
        BackupExecution.query.filter(BackupExecution.id.in_(backup_ids)).delete(synchronize_session=False)
        db.session.commit()

        flash('All backups have been deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        safe_msg = sanitize_error_message(e, "Error deleting backups")
        flash(safe_msg, 'danger')

    return redirect(url_for('backups.backups'))
