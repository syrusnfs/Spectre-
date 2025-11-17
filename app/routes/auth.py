"""
Authentication routes (login, logout, 2FA)
"""
import time as time_module
import hmac
import pyotp
import qrcode
import io
import base64
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash
from app.extensions import db
from app.models import User
from app.security import sanitize_input, hash_password, require_otp_verification
from app.security.encryption import decrypt_credential

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'), 80)
        password = request.form.get('password')  # Don't sanitize password

        if not username:
            flash('Invalid username', 'danger')
            return render_template('login.html'), 401

        user = User.query.filter_by(username=username).first()

        # PREVENT USERNAME ENUMERATION: Perform fake hash if user doesn't exist
        if user:
            password_valid = check_password_hash(user.password_hash, password)
        else:
            # Fake hash to maintain constant timing
            check_password_hash(hash_password('fake_password_xyz123'), password)
            password_valid = False

        # Fixed delay to prevent timing attacks
        time_module.sleep(0.3)

        if user and password_valid:
            # PREVENT SESSION FIXATION: Regenerate session ID
            session.clear()
            session.permanent = True

            # If 2FA is enabled, redirect to OTP verification
            if user.otp_enabled:
                session['otp_user_id'] = user.id
                return redirect(url_for('auth.verify_otp'))

            # Direct login if 2FA is not enabled
            login_user(user)
            session.modified = True  # Force session ID regeneration

            next_page = request.args.get('next')
            # Prevent open redirect
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('main.index'))
        else:
            # VULN-010: Log failed login attempt
            from flask import current_app
            current_app.logger.warning(f'[AUDIT] Failed login for username: {username}')
            flash('Invalid credentials', 'danger')
            return render_template('login.html'), 401

    return render_template('login.html')


@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp_user_id' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip()
        user = User.query.get(session['otp_user_id'])

        if user and user.otp_secret:
            totp = pyotp.TOTP(user.otp_secret)
            expected_otp = totp.now()

            # PREVENT TIMING ATTACK: Constant-time comparison
            is_valid = hmac.compare_digest(expected_otp, otp_code)

            if is_valid:
                session.pop('otp_user_id', None)

                # PREVENT SESSION FIXATION after OTP
                login_user(user)
                session.modified = True  # Force session ID regeneration

                flash('Login successful!', 'success')
                return redirect(url_for('main.index'))
            else:
                # VULN-010: Log failed OTP attempt
                from flask import current_app
                current_app.logger.warning(f'[AUDIT] Invalid OTP for user ID: {session.get("otp_user_id")}')
                # Fixed delay after failure (prevent timing attack)
                time_module.sleep(0.5)
                flash('Invalid OTP code', 'danger')
                return render_template('verify_otp.html'), 401
        else:
            # VULN-010: Log 2FA verification error
            from flask import current_app
            current_app.logger.error(f'[AUDIT] 2FA verification error for user ID: {session.get("otp_user_id")}')
            time_module.sleep(0.5)
            flash('2FA verification error', 'danger')
            return redirect(url_for('auth.login'))

    return render_template('verify_otp.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('otp_user_id', None)
    return redirect(url_for('auth.login'))


@auth_bp.route('/verify_otp_action', methods=['POST'])
@login_required
def verify_otp_action():
    """Verify OTP for critical actions (delete users, backups, logs)"""

    # Check if user has 2FA enabled
    if not current_user.otp_enabled or not current_user.otp_secret:
        return jsonify({
            'success': False,
            'message': '2FA is not configured. Critical actions require two-factor authentication.'
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

    # Valid OTP - generate temporary token in session
    session['otp_verified_at'] = time_module.time()

    return jsonify({
        'success': True,
        'message': 'OTP verified successfully'
    })
