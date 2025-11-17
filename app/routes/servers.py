"""
Server management routes
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Server
from app.security import sanitize_input, validate_port, require_otp_verification
from app.security.encryption import encrypt_credential

servers_bp = Blueprint('servers', __name__, url_prefix='/servers')


@servers_bp.route('/')
@login_required
def servers():
    # Admin sees all servers, User sees only their own
    if current_user.is_admin():
        servers = Server.query.order_by(Server.user_id, Server.name).all()
    else:
        servers = Server.query.filter_by(user_id=current_user.id).all()

    return render_template('servers.html', servers=servers)


@servers_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_server():
    if request.method == 'POST':
        name = sanitize_input(request.form.get('name'), 200)
        host = sanitize_input(request.form.get('host'), 255)
        port = request.form.get('port', 22)
        username = sanitize_input(request.form.get('username'), 100)

        # Validate port
        if not validate_port(port):
            flash('Invalid port (1-65535)', 'danger')
            return redirect(url_for('servers.add_server'))

        # Encrypt credentials
        password = request.form.get('password') if request.form.get('auth_type') == 'password' else None
        ssh_key = request.form.get('ssh_key') if request.form.get('auth_type') == 'key' else None

        server = Server(
            name=name,
            host=host,
            port=int(port),
            username=username,
            auth_type=request.form.get('auth_type'),
            password=encrypt_credential(password) if password else None,
            ssh_key=encrypt_credential(ssh_key) if ssh_key else None,
            user_id=current_user.id
        )
        db.session.add(server)
        db.session.commit()
        flash('Server added successfully!', 'success')
        return redirect(url_for('servers.servers'))

    return render_template('add_server.html')


@servers_bp.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_server(id):
    server = Server.query.get_or_404(id)

    # IDOR Protection: Admin can edit any server, User can only edit their own
    if not current_user.is_admin() and server.user_id != current_user.id:
        current_app.logger.warning(f'[AUDIT] Unauthorized access attempt to server ID {id} by user {current_user.username}')
        flash('Access denied', 'danger')
        return redirect(url_for('servers.servers'))

    if request.method == 'POST':
        server.name = request.form.get('name')
        server.host = request.form.get('host')
        server.port = int(request.form.get('port', 22))
        server.username = request.form.get('username')
        server.auth_type = request.form.get('auth_type')

        if request.form.get('auth_type') == 'password':
            pwd = request.form.get('password')
            server.password = encrypt_credential(pwd) if pwd else server.password
            server.ssh_key = None
        else:
            key = request.form.get('ssh_key')
            server.ssh_key = encrypt_credential(key) if key else server.ssh_key
            server.password = None

        db.session.commit()
        flash('Server updated successfully!', 'success')
        return redirect(url_for('servers.servers'))

    return render_template('edit_server.html', server=server)


@servers_bp.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_server(id):
    # Verify OTP before proceeding
    if not require_otp_verification():
        return redirect(url_for('servers.servers'))

    server = Server.query.get_or_404(id)

    # IDOR Protection: Admin can delete any server, User can only delete their own
    if not current_user.is_admin() and server.user_id != current_user.id:
        current_app.logger.warning(f'[AUDIT] Attempt to delete server ID {id} by unauthorized user {current_user.username}')
        flash('Access denied', 'danger')
        return redirect(url_for('servers.servers'))

    # Audit log
    current_app.logger.info(f'[AUDIT] Server {server.name} (ID: {id}) deleted by {current_user.username} (role: {current_user.role})')

    db.session.delete(server)
    db.session.commit()
    flash('Server removed successfully!', 'success')
    return redirect(url_for('servers.servers'))
