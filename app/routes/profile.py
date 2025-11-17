"""
User profile routes
"""
import pyotp
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from app.security.encryption import decrypt_credential

profile_bp = Blueprint('profile', __name__, url_prefix='/profile')


@profile_bp.route('/backup-key', methods=['GET', 'POST'])
@login_required
def view_my_backup_key():
    # Check if user has 2FA enabled
    if not current_user.otp_enabled:
        flash('You must enable two-factor authentication (2FA) before accessing the backup key', 'warning')
        return redirect(url_for('main.index'))

    # Verify OTP before showing
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')

        # Validate OTP code
        if not otp_code or not pyotp.TOTP(current_user.otp_secret).verify(otp_code, valid_window=1):
            flash('Invalid OTP code', 'danger')
            return redirect(url_for('profile.view_my_backup_key'))

        # Decrypt backup password
        try:
            backup_key = decrypt_credential(current_user.backup_password)

            # Audit log
            current_app.logger.info(f'[AUDIT] User {current_user.username} (ID: {current_user.id}) viewed their backup key')

            return render_template('view_backup_key.html', user=current_user, backup_key=backup_key, is_admin_view=False)
        except Exception:
            flash('Error decrypting backup key', 'danger')
            return redirect(url_for('main.index'))

    return render_template('confirm_view_backup_key.html', user=current_user, is_admin_view=False)
