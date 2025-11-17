"""
User management routes
"""
import pyotp
import qrcode
import io
import base64
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from app.extensions import db
from app.models import User
from app.security import (
    sanitize_input,
    validate_email,
    hash_password,
    generate_backup_password,
    admin_required,
    require_otp_verification
)
from app.security.encryption import encrypt_credential, decrypt_credential

users_bp = Blueprint('users', __name__, url_prefix='/users')


@users_bp.route('/')
@login_required
@admin_required
def users():
    users = User.query.all()
    return render_template('users.html', users=users)


@users_bp.route('/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        # Verify OTP before proceeding
        if not require_otp_verification():
            return redirect(url_for('users.users'))

        username = sanitize_input(request.form.get('username'), 80)
        password = request.form.get('password')
        role = request.form.get('role', 'user')

        # Validate role
        if role not in ['admin', 'user']:
            flash('Invalid role', 'danger')
            return redirect(url_for('users.add_user'))

        # Validate email
        try:
            email = validate_email(request.form.get('email'))
        except ValueError as e:
            flash(f'Invalid email: {str(e)}', 'danger')
            return redirect(url_for('users.add_user'))

        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return redirect(url_for('users.add_user'))

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('A user with this username already exists', 'danger')
            return redirect(url_for('users.add_user'))

        if User.query.filter_by(email=email).first():
            flash('A user with this email already exists', 'danger')
            return redirect(url_for('users.add_user'))

        # Generate and encrypt unique backup_password for this user
        backup_pwd = generate_backup_password()
        encrypted_backup_pwd = encrypt_credential(backup_pwd)

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            backup_password=encrypted_backup_pwd,
            role=role
        )
        db.session.add(user)
        db.session.commit()

        # Audit log
        current_app.logger.info(f'[AUDIT] New user created: {username} (role: {role}) by admin {current_user.username}')

        flash(f'User {username} ({role}) added successfully!', 'success')
        return redirect(url_for('users.users'))

    return render_template('add_user.html')


@users_bp.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    user = User.query.get_or_404(id)

    # PREVENT IDOR: User can only edit themselves
    if user.id != current_user.id:
        # VULN-010: Log unauthorized access attempt
        current_app.logger.warning(f'[AUDIT] Attempt to edit user by another user. Current user: {current_user.id}, Target: {id}')
        flash('Access denied', 'danger')
        return redirect(url_for('users.users'))

    if request.method == 'POST':
        username = request.form.get('username')

        # Validate email
        try:
            email = validate_email(request.form.get('email'))
        except ValueError as e:
            flash(f'Invalid email: {str(e)}', 'danger')
            return redirect(url_for('users.edit_user', id=id))

        password = request.form.get('password')

        # Check if username already exists (except for this user)
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != user.id:
            flash('A user with this username already exists', 'danger')
            return redirect(url_for('users.edit_user', id=id))

        # Check if email already exists (except for this user)
        existing_email = User.query.filter_by(email=email).first()
        if existing_email and existing_email.id != user.id:
            flash('A user with this email already exists', 'danger')
            return redirect(url_for('users.edit_user', id=id))

        user.username = username
        user.email = email

        # Only update password if a new one was provided
        if password:
            user.password_hash = hash_password(password)

        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('users.users'))

    return render_template('edit_user.html', user=user)


@users_bp.route('/<int:user_id>/2fa/setup')
@login_required
def setup_2fa_user(user_id):
    user = User.query.get_or_404(user_id)

    # PREVENT IDOR: User can only configure 2FA for themselves, except admin
    if user.id != current_user.id and not current_user.is_admin():
        flash('Access denied', 'danger')
        return redirect(url_for('users.users'))

    # Generate new secret if it doesn't exist
    if not user.otp_secret:
        secret = pyotp.random_base32()
        user.otp_secret = secret
        db.session.commit()
    else:
        secret = user.otp_secret

    # Generate QR Code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='Spectre'
    )

    # Create QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template('setup_2fa.html',
                         user=user,
                         qr_code=qr_code_base64,
                         secret=secret,
                         otp_enabled=user.otp_enabled)


@users_bp.route('/<int:user_id>/2fa/enable', methods=['POST'])
@login_required
def enable_2fa_user(user_id):
    user = User.query.get_or_404(user_id)

    # PREVENT IDOR: User can only enable 2FA for themselves, except admin
    if user.id != current_user.id and not current_user.is_admin():
        flash('Access denied', 'danger')
        return redirect(url_for('users.users'))

    otp_code = request.form.get('otp_code', '').strip()

    if not user.otp_secret:
        flash('Configure 2FA first', 'danger')
        return redirect(url_for('users.setup_2fa_user', user_id=user_id))

    totp = pyotp.TOTP(user.otp_secret)
    if totp.verify(otp_code, valid_window=1):
        user.otp_enabled = True
        db.session.commit()
        flash(f'2FA enabled successfully for {user.username}!', 'success')
    else:
        flash('Invalid OTP code. Please try again.', 'danger')

    return redirect(url_for('users.setup_2fa_user', user_id=user_id))


@users_bp.route('/verify-otp-backup-password', methods=['POST'])
@login_required
def verify_otp_backup_password():
    """Verifies OTP and returns BACKUP_PASSWORD if valid"""

    # Check if the user has 2FA enabled
    if not current_user.otp_enabled or not current_user.otp_secret:
        return jsonify({
            'success': False,
            'message': '2FA is not configured for this user'
        }), 403

    # Get OTP code from request
    data = request.get_json()
    otp_code = data.get('otp_code', '').strip()

    if not otp_code or len(otp_code) != 6:
        return jsonify({
            'success': False,
            'message': 'Invalid OTP code'
        }), 400

    # Verify OTP code
    totp = pyotp.TOTP(current_user.otp_secret)
    if not totp.verify(otp_code, valid_window=1):
        return jsonify({
            'success': False,
            'message': 'Incorrect OTP code'
        }), 401

    # Valid OTP, return user's BACKUP_PASSWORD
    if not current_user.backup_password:
        return jsonify({
            'success': False,
            'message': 'BACKUP_PASSWORD not configured for this user'
        }), 500

    # Decrypt user's backup_password
    backup_password = decrypt_credential(current_user.backup_password)

    if not backup_password:
        return jsonify({
            'success': False,
            'message': 'Error decrypting BACKUP_PASSWORD'
        }), 500

    # Audit log
    current_app.logger.info(f'BACKUP_PASSWORD viewed by user {current_user.username} (ID: {current_user.id})')

    return jsonify({
        'success': True,
        'backup_password': backup_password
    })


@users_bp.route('/change-password/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def change_user_password(id):
    user = User.query.get_or_404(id)

    if request.method == 'POST':
        # Verify OTP before proceeding
        if not require_otp_verification():
            return redirect(url_for('users.users'))

        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validate passwords
        if not new_password or len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('users.change_user_password', id=id))

        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('users.change_user_password', id=id))

        # Change password
        user.password_hash = hash_password(new_password)
        db.session.commit()

        # Audit log
        current_app.logger.info(f'[AUDIT] Password changed for user {user.username} (ID: {user.id}) by admin {current_user.username}')

        flash(f'Password for {user.username} changed successfully!', 'success')
        return redirect(url_for('users.users'))

    return render_template('change_user_password.html', user=user)


@users_bp.route('/view-backup-key/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def view_user_backup_key(id):
    user = User.query.get_or_404(id)

    # Check if admin has 2FA enabled (required for access)
    if not current_user.otp_enabled:
        flash('You must have 2FA enabled to access backup keys', 'danger')
        return redirect(url_for('users.users'))

    # Verify OTP before showing
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')

        # Validate OTP code
        if not otp_code or not pyotp.TOTP(current_user.otp_secret).verify(otp_code, valid_window=1):
            flash('Invalid OTP code', 'danger')
            return redirect(url_for('users.view_user_backup_key', id=id))

        # Decrypt backup password
        try:
            backup_key = decrypt_credential(user.backup_password)

            # Audit log
            current_app.logger.warning(f'[AUDIT] Backup key viewed for user {user.username} (ID: {user.id}) by admin {current_user.username}')

            return render_template('view_backup_key.html', user=user, backup_key=backup_key, is_admin_view=True)
        except Exception:
            flash('Error decrypting backup key', 'danger')
            return redirect(url_for('users.users'))

    return render_template('confirm_view_backup_key.html', user=user, is_admin_view=True)


@users_bp.route('/delete/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_user(id):
    # Verify OTP before proceeding
    if not require_otp_verification():
        return redirect(url_for('users.users'))

    user = User.query.get_or_404(id)

    # Don't allow deleting yourself
    if user.id == current_user.id:
        flash('You cannot delete your own user account', 'danger')
        return redirect(url_for('users.users'))

    # Don't allow deleting if this is the last admin
    if user.is_admin():
        admin_count = User.query.filter_by(role='admin').count()
        if admin_count <= 1:
            flash('Cannot delete the last system administrator', 'danger')
            return redirect(url_for('users.users'))

    # VULN-010: Audit log before deletion
    current_app.logger.info(f'[AUDIT] User deleted: {user.username} (ID: {user.id}, role: {user.role}) by admin {current_user.username}')

    db.session.delete(user)
    db.session.commit()
    flash('User removed successfully!', 'success')
    return redirect(url_for('users.users'))
