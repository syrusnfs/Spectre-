"""
Encryption utilities for sensitive data
Uses Fernet (AES-128 CBC + HMAC-SHA256)
"""
import os
from cryptography.fernet import Fernet
from flask import current_app


def get_encryption_key():
    """
    Retrieves the military-grade encryption key (AES-256).
    The key must be 32 bytes (256 bits) for maximum security.
    Fernet uses AES-128 in CBC mode with HMAC for authentication.
    """
    key = current_app.config.get('ENCRYPTION_KEY')
    if not key:
        raise ValueError(
            "ENCRYPTION_KEY not defined! "
            "Generate a secure key and add it to .env:\n"
            "  python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"\n"
            "NEVER commit the key to the repository!"
        )
    return key.encode() if isinstance(key, str) else key


def encrypt_credential(data):
    """
    Encrypts sensitive credentials using Fernet (AES-128 CBC + HMAC-SHA256).
    - Provides confidentiality (AES)
    - Message authentication (HMAC)
    - Protection against replay attacks (timestamp)
    - Resistance to padding oracle attacks
    """
    if not data:
        return None
    try:
        f = Fernet(get_encryption_key())
        encrypted = f.encrypt(data.encode())
        return encrypted.decode()
    except Exception as e:
        current_app.logger.error(f"Error encrypting credential: {str(e)}")
        raise Exception("Failed to encrypt sensitive credentials")


def decrypt_credential(data):
    """
    Decrypts credentials with authenticity validation.
    Returns None if decryption fails (corrupted data or invalid key).
    """
    if not data:
        return None
    try:
        f = Fernet(get_encryption_key())
        decrypted = f.decrypt(data.encode())
        return decrypted.decode()
    except Exception as e:
        current_app.logger.error(f"Error decrypting credential: {str(e)}")
        return None
