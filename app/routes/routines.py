"""
Backup routine management routes
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from app.extensions import db
from app.models import BackupRoutine, Server
from app.security import sanitize_path, require_otp_verification
from app.services.backup_service import execute_backup

routines_bp = Blueprint('routines', __name__, url_prefix='/routines')

# Global scheduler reference (will be injected by app factory)
_scheduler = None
_app = None


def init_routines_blueprint(scheduler, app):
    """Initialize blueprint with scheduler reference"""
    global _scheduler, _app
    _scheduler = scheduler
    _app = app


@routines_bp.route('/')
@login_required
def routines():
    # Admin sees all routines, User sees only their own
    if current_user.is_admin():
        routines = BackupRoutine.query.order_by(BackupRoutine.user_id, BackupRoutine.name).all()
    else:
        routines = BackupRoutine.query.filter_by(user_id=current_user.id).all()

    return render_template('routines.html', routines=routines)


@routines_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_routine():
    if request.method == 'POST':
        try:
            remote_path = sanitize_path(request.form.get('remote_path'))
        except ValueError as e:
            flash(f'Validation error: {str(e)}', 'danger')
            return redirect(url_for('routines.add_routine'))

        # Validate remote path
        if not remote_path:
            flash('Invalid remote path', 'danger')
            return redirect(url_for('routines.add_routine'))

        # PREVENT IDOR: Validate that server_id belongs to current user (or admin can access any)
        server_id = int(request.form.get('server_id'))
        server = Server.query.get(server_id)
        if not server:
            flash('Invalid server', 'danger')
            return redirect(url_for('routines.add_routine'))

        # Regular user can only choose their own servers, Admin can choose any
        if not current_user.is_admin() and server.user_id != current_user.id:
            flash('Access denied to selected server', 'danger')
            return redirect(url_for('routines.add_routine'))

        # Use BACKUP_BASE_PATH from config as fixed local_path
        import os
        local_path = os.getenv('BACKUP_BASE_PATH', '/opt/backups')

        routine = BackupRoutine(
            name=request.form.get('name'),
            server_id=server_id,
            remote_path=remote_path,
            local_path=local_path,
            schedule_type=request.form.get('schedule_type'),
            schedule_time=request.form.get('schedule_time'),
            retention_days=int(request.form.get('retention_days', 30)),
            enabled=request.form.get('enabled') == 'on',
            user_id=server.user_id  # Routine belongs to server owner
        )
        db.session.add(routine)
        db.session.commit()

        # Update scheduler
        if _scheduler and _app:
            from app.services.scheduler_service import update_routine_schedule
            update_routine_schedule(routine, _scheduler, _app)

        flash('Routine created successfully!', 'success')
        return redirect(url_for('routines.routines'))

    # Admin sees all servers, User sees only their own
    if current_user.is_admin():
        servers = Server.query.order_by(Server.user_id, Server.name).all()
    else:
        servers = Server.query.filter_by(user_id=current_user.id).all()

    return render_template('add_routine.html', servers=servers)


@routines_bp.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_routine(id):
    routine = BackupRoutine.query.get_or_404(id)

    # IDOR Protection: Admin can edit any routine, User can only edit their own
    if not current_user.is_admin() and routine.user_id != current_user.id:
        current_app.logger.warning(f'[AUDIT] Unauthorized access attempt to routine ID {id} by user {current_user.username}')
        flash('Access denied', 'danger')
        return redirect(url_for('routines.routines'))

    if request.method == 'POST':
        try:
            remote_path = sanitize_path(request.form.get('remote_path'))
        except ValueError as e:
            flash(f'Validation error: {str(e)}', 'danger')
            return redirect(url_for('routines.edit_routine', id=id))

        # Validate remote path
        if not remote_path:
            flash('Invalid remote path', 'danger')
            return redirect(url_for('routines.edit_routine', id=id))

        routine.name = request.form.get('name')

        # PREVENT IDOR: Validate that server_id belongs to current user (or admin can access any)
        new_server_id = int(request.form.get('server_id'))
        server = Server.query.get(new_server_id)
        if not server:
            flash('Invalid server', 'danger')
            return redirect(url_for('routines.edit_routine', id=id))

        # Regular user can only choose their own servers, Admin can choose any
        if not current_user.is_admin() and server.user_id != current_user.id:
            flash('Access denied to selected server', 'danger')
            return redirect(url_for('routines.edit_routine', id=id))

        # Use BACKUP_BASE_PATH from config as fixed local_path
        import os
        local_path = os.getenv('BACKUP_BASE_PATH', '/opt/backups')

        routine.server_id = new_server_id
        routine.remote_path = remote_path
        routine.local_path = local_path
        routine.schedule_type = request.form.get('schedule_type')
        routine.schedule_time = request.form.get('schedule_time')
        routine.retention_days = int(request.form.get('retention_days', 30))
        routine.enabled = request.form.get('enabled') == 'on'

        db.session.commit()

        # Update scheduler
        if _scheduler and _app:
            from app.services.scheduler_service import update_routine_schedule
            update_routine_schedule(routine, _scheduler, _app)

        flash('Routine updated successfully!', 'success')
        return redirect(url_for('routines.routines'))

    # Admin sees all servers, User sees only their own
    if current_user.is_admin():
        servers = Server.query.order_by(Server.user_id, Server.name).all()
    else:
        servers = Server.query.filter_by(user_id=current_user.id).all()

    return render_template('edit_routine.html', routine=routine, servers=servers)


@routines_bp.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_routine(id):
    # Verify OTP before proceeding
    if not require_otp_verification():
        return redirect(url_for('routines.routines'))

    routine = BackupRoutine.query.get_or_404(id)

    # IDOR Protection: Admin can delete any routine, User can only delete their own
    if not current_user.is_admin() and routine.user_id != current_user.id:
        current_app.logger.warning(f'[AUDIT] Attempt to delete routine ID {id} by unauthorized user {current_user.username}')
        flash('Access denied', 'danger')
        return redirect(url_for('routines.routines'))

    # Remove from scheduler
    if _scheduler:
        try:
            _scheduler.remove_job(f'routine_{id}')
        except:
            pass

    db.session.delete(routine)
    db.session.commit()
    flash('Routine removed successfully!', 'success')
    return redirect(url_for('routines.routines'))


@routines_bp.route('/run/<int:id>', methods=['POST'])
@login_required
def run_routine(id):
    routine = BackupRoutine.query.get_or_404(id)

    # IDOR Protection: Admin can execute any routine, User can only execute their own
    if not current_user.is_admin() and routine.user_id != current_user.id:
        current_app.logger.warning(f'[AUDIT] Attempt to execute routine ID {id} by unauthorized user {current_user.username}')
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    success, message = execute_backup(routine)
    return jsonify({'success': success, 'message': message})
