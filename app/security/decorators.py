"""
Security decorators for route protection
"""
import time as time_module
from functools import wraps
from flask import flash, redirect, url_for, request, session
from flask import current_app
from flask_login import current_user


def admin_required(f):
    """
    Decorator to protect routes that only admins can access

    Usage:
        @app.route('/admin/users')
        @login_required
        @admin_required
        def admin_users():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Login required', 'danger')
            return redirect(url_for('auth.login'))

        if not current_user.is_admin():
            # Log unauthorized access attempt
            current_app.logger.warning(
                f'[AUDIT] Admin access attempt by non-admin user. '
                f'User: {current_user.username} (ID: {current_user.id}), '
                f'Route: {request.endpoint}'
            )
            flash('Access denied. This area is restricted to administrators.', 'danger')
            return redirect(url_for('main.index'))

        return f(*args, **kwargs)

    return decorated_function


def require_otp_verification():
    """
    Checks if OTP was validated recently (last 30 seconds)

    Returns:
        bool: True if OTP is valid, False otherwise
    """
    if not current_user.otp_enabled:
        flash('Critical actions require two-factor authentication (2FA). Please configure 2FA first.', 'error')
        return False

    otp_verified_at = session.get('otp_verified_at')
    if not otp_verified_at or (time_module.time() - otp_verified_at) > 30:
        flash('OTP verification required for this action.', 'error')
        return False

    # Clear OTP verification from session after use
    session.pop('otp_verified_at', None)
    return True
