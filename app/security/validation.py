"""
Input validation and sanitization utilities
"""
import os
import re
import secrets
from werkzeug.security import generate_password_hash
from flask import current_app
from flask_login import current_user


def sanitize_path(path, allow_absolute=True):
    """
    Validates and sanitizes paths to prevent path traversal

    Args:
        path: Path to validate
        allow_absolute: If True, allows absolute paths (for remote servers)

    Returns:
        Sanitized path or None if invalid

    Raises:
        ValueError: If path contains dangerous characters or path traversal
    """
    if not path:
        return None

    # Remove whitespace
    path = path.strip()

    if not path:
        return None

    # Check for dangerous characters
    dangerous_chars = ['\0', '\n', '\r', '\t', '|', ';', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>']
    for char in dangerous_chars:
        if char in path:
            raise ValueError(f"Path contains invalid character: {repr(char)}")

    # Split path into parts
    parts = path.replace('\\', '/').split('/')

    # Check for path traversal in each part
    for part in parts:
        if part == '..':
            raise ValueError("Path traversal (..) is not allowed")
        # Check for variations of '..'
        if '..' in part:
            raise ValueError("Path traversal detected")

    # Normalize path (use forward slashes for SFTP)
    normalized = '/'.join(parts)

    # Remove multiple consecutive slashes
    while '//' in normalized:
        normalized = normalized.replace('//', '/')

    # Check if it's an absolute path when not allowed
    if not allow_absolute and normalized.startswith('/'):
        raise ValueError("Absolute paths are not allowed")

    return normalized


def sanitize_input(text, max_length=255):
    """Sanitizes inputs to prevent injection"""
    if not text:
        return None
    text = str(text).strip()[:max_length]
    # Remove dangerous control characters
    text = ''.join(char for char in text if char.isprintable() or char in ['\n', '\r', '\t'])
    return text


def sanitize_error_message(error, generic_message="An error occurred"):
    """
    VULN-011: Information Disclosure via Error Messages

    Sanitizes error messages to avoid exposing system details to the user.
    Complete logs are kept on the server.

    Args:
        error: Exception or error string
        generic_message: Generic message to show to the user

    Returns:
        Sanitized message safe to show to the user
    """
    error_str = str(error)

    # List of sensitive patterns that should not be exposed
    sensitive_patterns = [
        'Traceback',
        'File "',
        'line ',
        'Error:',
        os.path.expanduser('~'),  # System user path
        'c:\\',  # Windows paths
        '/home/',  # Linux paths
        '/var/',
        '/etc/',
        'mysql',
        'postgres',
        'sqlite',
        'permission denied',
        'access denied',
    ]

    # Check if error contains sensitive information
    error_lower = error_str.lower()
    for pattern in sensitive_patterns:
        if pattern.lower() in error_lower:
            current_app.logger.error(f'[SANITIZED ERROR] {error_str}')  # Full log on server
            return generic_message

    # If it doesn't contain sensitive patterns, return basic message
    # Never return the complete exception
    return generic_message


def validate_port(port):
    """Validates port number"""
    try:
        port = int(port)
        return 1 <= port <= 65535
    except:
        return False


def validate_email(email):
    """
    Validates and normalizes email address

    Args:
        email: Email to validate

    Returns:
        Normalized email (lowercase)

    Raises:
        ValueError: If email is invalid
    """
    if not email:
        raise ValueError("Email cannot be empty")

    email = email.strip().lower()

    # Basic but effective validation using regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not re.match(email_pattern, email):
        raise ValueError("Invalid email format")

    # Additional checks
    if '..' in email:
        raise ValueError("Email cannot contain consecutive dots")

    if email.startswith('.') or email.startswith('@'):
        raise ValueError("Invalid email")

    local_part, domain = email.split('@')

    if len(local_part) > 64:
        raise ValueError("Email local part too long (max 64 characters)")

    if len(domain) > 255:
        raise ValueError("Email domain too long (max 255 characters)")

    return email


def validate_access(resource_user_id):
    """Validates if the current user has access to the resource"""
    from flask import flash
    if resource_user_id != current_user.id:
        flash('Access denied', 'danger')
        return False
    return True


def hash_password(password):
    """
    Creates secure password hash using PBKDF2-SHA256 with 600k iterations (OWASP 2023)

    Args:
        password: Password in plaintext

    Returns:
        Password hash
    """
    method = current_app.config.get('PASSWORD_HASH_METHOD', 'pbkdf2:sha256:600000')
    return generate_password_hash(password, method=method)


def generate_backup_password():
    """Generates a secure password for backups (32 URL-safe characters)"""
    return secrets.token_urlsafe(32)
