"""
Backup execution and management service
"""
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import pyzipper
from flask import current_app
from app.extensions import db
from app.models import BackupLog, BackupExecution, User
from app.security.encryption import decrypt_credential
from app.services.sftp_service import (
    get_ssh_client,
    get_directory_size,
    download_directory,
    create_sftp_directory_recursive
)
from app.security.validation import sanitize_path


def log_message(routine_id, level, message):
    """Adds a log entry"""
    log = BackupLog(routine_id=routine_id, level=level, message=message)
    db.session.add(log)
    db.session.commit()


def create_encrypted_backup(source_dir, output_path, password):
    """
    Creates a password-protected ZIP archive using AES-256

    Args:
        source_dir: Directory to compress
        output_path: Path to output ZIP archive
        password: Password for encryption

    Returns:
        int: Size of created archive in bytes
    """
    # Use pyzipper to create ZIP with AES-256 encryption
    with pyzipper.AESZipFile(output_path, 'w', compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zipf:
        zipf.setpassword(password.encode('utf-8'))

        # Add all files from directory
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, os.path.dirname(source_dir))
                zipf.write(file_path, arcname)

    return os.path.getsize(output_path)


def execute_backup(routine):
    """Executes a complete backup and compresses it into an encrypted ZIP"""
    execution = BackupExecution(
        routine_id=routine.id,
        status='running',
        start_time=datetime.utcnow()
    )
    db.session.add(execution)
    db.session.commit()

    log_message(routine.id, 'info', f'Starting backup: {routine.name}')

    ssh = None
    sftp = None
    temp_dir = None

    try:
        server = db.session.get(routine.server.__class__, routine.server_id)
        log_message(routine.id, 'info', f'Connecting to server {server.host}...')
        ssh = get_ssh_client(server)
        sftp = ssh.open_sftp()

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"{routine.name}_{timestamp}"

        # Create temporary directory for download
        backup_base_path = current_app.config.get('BACKUP_BASE_PATH')
        if os.path.isabs(routine.local_path):
            base_path = routine.local_path
        else:
            base_path = os.path.join(backup_base_path, routine.local_path)

        os.makedirs(base_path, exist_ok=True)
        temp_dir = os.path.join(base_path, f"temp_{backup_name}")
        os.makedirs(temp_dir, exist_ok=True)

        # Ensure remote_path uses forward slashes (SFTP/Linux)
        remote_path = routine.remote_path.replace('\\', '/')

        log_message(routine.id, 'info', f'Calculating backup size...')
        total_size, files_count = get_directory_size(sftp, remote_path)
        log_message(routine.id, 'info', f'Found {files_count} files ({total_size / (1024*1024):.2f} MB)')

        log_message(routine.id, 'info', 'Starting file transfer...')
        download_directory(sftp, remote_path, temp_dir)

        # Compress and encrypt with password
        log_message(routine.id, 'info', 'Compressing and encrypting backup with AES-256...')

        # Get backup_password from routine owner user
        user = db.session.get(User, routine.user_id)
        if not user or not user.backup_password:
            raise Exception("User does not have backup_password configured")

        # Decrypt user's backup_password
        backup_password = decrypt_credential(user.backup_password)
        if not backup_password:
            raise Exception("Error decrypting user's backup_password")

        zip_path = os.path.join(base_path, f"{backup_name}.zip")

        # Create encrypted backup with AES-256 using user's password
        compressed_size = create_encrypted_backup(temp_dir, zip_path, backup_password)

        compression_ratio = (1 - compressed_size / total_size) * 100 if total_size > 0 else 0

        log_message(routine.id, 'info',
                   f'Compression and encryption completed! Original size: {total_size / (1024*1024):.2f} MB, '
                   f'Compressed and encrypted (AES-256): {compressed_size / (1024*1024):.2f} MB '
                   f'({compression_ratio:.1f}% reduction)')

        # Remove temporary directory
        shutil.rmtree(temp_dir)
        temp_dir = None

        execution.end_time = datetime.utcnow()
        execution.status = 'success'
        execution.files_count = files_count
        execution.total_size = compressed_size  # Store compressed size
        execution.backup_path = zip_path
        routine.last_run = datetime.utcnow()
        db.session.commit()

        log_message(routine.id, 'info', f'Backup completed successfully! {files_count} files saved, compressed and encrypted with AES-256.')
        cleanup_old_backups(routine)

        return True, f'Backup completed successfully! {files_count} files compressed and encrypted (AES-256) in {compressed_size / (1024*1024):.2f} MB.'

    except Exception as e:
        error_msg = str(e)
        log_message(routine.id, 'error', f'Backup error: {error_msg}')
        execution.end_time = datetime.utcnow()
        execution.status = 'failed'
        execution.error_message = error_msg
        db.session.commit()

        # Clean up temporary directory on error
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except:
                pass

        return False, f'Backup error: {error_msg}'

    finally:
        # Ensure both are closed even if one fails
        if sftp:
            try:
                sftp.close()
            except Exception as e:
                current_app.logger.error(f"Error closing SFTP: {e}")

        if ssh:
            try:
                ssh.close()
            except Exception as e:
                current_app.logger.error(f"Error closing SSH: {e}")


def cleanup_old_backups(routine):
    """Removes old backups based on retention policy (encrypted .zip archives)"""
    try:
        backup_base_path = current_app.config.get('BACKUP_BASE_PATH')
        # Use relative path to backups folder or absolute path
        if os.path.isabs(routine.local_path):
            backup_dir = Path(routine.local_path)
        else:
            backup_dir = Path(os.path.join(backup_base_path, routine.local_path))

        if not backup_dir.exists():
            return

        backups = []
        # Search for .zip (encrypted) or .tar.gz (legacy) archives starting with routine name
        for item in backup_dir.iterdir():
            if item.is_file() and item.name.startswith(routine.name) and (item.name.endswith('.zip') or item.name.endswith('.tar.gz')):
                backups.append(item)

        backups.sort(key=lambda x: x.stat().st_mtime, reverse=True)

        cutoff_date = datetime.now() - timedelta(days=routine.retention_days)

        for backup in backups:
            backup_time = datetime.fromtimestamp(backup.stat().st_mtime)
            if backup_time < cutoff_date:
                os.remove(backup)
                log_message(routine.id, 'info', f'Old backup removed: {backup.name}')

    except Exception as e:
        log_message(routine.id, 'warning', f'Error cleaning up old backups: {str(e)}')


def restore_backup_to_server(backup_execution):
    """
    Restores an encrypted backup to the original server

    Args:
        backup_execution: BackupExecution object with backup information

    Returns:
        tuple: (success: bool, message: str)
    """
    ssh = None
    sftp = None
    temp_extract_dir = None

    try:
        routine = backup_execution.routine
        server = routine.server
        backup_path = backup_execution.backup_path

        if not os.path.exists(backup_path):
            return False, 'Backup file not found on system'

        # Verify it's an encrypted backup (.zip)
        if not backup_path.endswith('.zip'):
            return False, 'Only encrypted backups (.zip) can be restored via web interface'

        current_app.logger.info(f'Starting restore of backup {backup_path} to server {server.name}')

        # Get backup_password from routine owner user
        user = db.session.get(User, routine.user_id)
        if not user or not user.backup_password:
            return False, 'User does not have backup_password configured'

        # Decrypt user's backup_password
        backup_password = decrypt_credential(user.backup_password)
        if not backup_password:
            return False, 'Error decrypting user\'s backup_password'

        # Create temporary directory for extraction
        backup_base_path = current_app.config.get('BACKUP_BASE_PATH')
        temp_extract_dir = os.path.join(backup_base_path, f'restore_temp_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
        os.makedirs(temp_extract_dir, exist_ok=True)

        current_app.logger.info(f'Extracting encrypted backup to {temp_extract_dir}...')

        # Extract encrypted backup
        try:
            with pyzipper.AESZipFile(backup_path, 'r') as zipf:
                zipf.setpassword(backup_password.encode('utf-8'))
                zipf.extractall(temp_extract_dir)
        except RuntimeError as e:
            if 'Bad password' in str(e):
                return False, 'Invalid encryption password. Backup cannot be extracted.'
            raise

        # Count extracted files
        files_count = sum([len(files) for _, _, files in os.walk(temp_extract_dir)])
        current_app.logger.info(f'{files_count} files extracted successfully')

        # Connect to server via SSH/SFTP
        current_app.logger.info(f'Connecting to server {server.name}...')
        ssh = get_ssh_client(server)
        sftp = ssh.open_sftp()

        # Validate remote path
        try:
            remote_path = sanitize_path(routine.remote_path)
        except ValueError as e:
            return False, f'Invalid path: {str(e)}'

        # Check if remote path exists, otherwise create using SFTP (secure)
        try:
            sftp.stat(remote_path)
        except IOError:
            current_app.logger.info(f'Creating remote directory {remote_path}...')
            create_sftp_directory_recursive(sftp, remote_path)

        current_app.logger.info(f'Uploading files to {remote_path}...')

        # Function to upload directory recursively
        def upload_directory(local_dir, remote_dir):
            for item in os.listdir(local_dir):
                local_item = os.path.join(local_dir, item)
                remote_item = os.path.join(remote_dir, item).replace('\\', '/')

                if os.path.isfile(local_item):
                    # Upload file
                    sftp.put(local_item, remote_item)
                    current_app.logger.debug(f'File uploaded: {remote_item}')
                elif os.path.isdir(local_item):
                    # Create remote directory if it doesn't exist
                    try:
                        sftp.stat(remote_item)
                    except IOError:
                        sftp.mkdir(remote_item)
                    # Recursively upload content
                    upload_directory(local_item, remote_item)

        # Upload all extracted files
        upload_directory(temp_extract_dir, remote_path)

        # Clean up temporary directory
        shutil.rmtree(temp_extract_dir)
        temp_extract_dir = None

        current_app.logger.info(f'Restore completed successfully! {files_count} files restored to {server.name}:{remote_path}')

        return True, f'Backup restored successfully! {files_count} files uploaded to {server.name}:{remote_path}'

    except Exception as e:
        current_app.logger.error(f'Restore error: {str(e)}')
        return False, f'Error restoring backup: {str(e)}'

    finally:
        # Clean up resources
        if temp_extract_dir and os.path.exists(temp_extract_dir):
            try:
                shutil.rmtree(temp_extract_dir)
            except Exception as e:
                current_app.logger.error(f"Error cleaning up temp_extract_dir: {e}")

        # Ensure both are closed even if one fails
        if sftp:
            try:
                sftp.close()
            except Exception as e:
                current_app.logger.error(f"Error closing SFTP: {e}")

        if ssh:
            try:
                ssh.close()
            except Exception as e:
                current_app.logger.error(f"Error closing SSH: {e}")
