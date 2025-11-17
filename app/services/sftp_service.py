"""
SFTP/SSH connection and file transfer service
"""
import os
import tempfile
import paramiko
from flask import current_app
from app.security.encryption import decrypt_credential


def get_ssh_client(server):
    """
    Creates and returns an SSH client configured with host key validation

    VULN-003: SSH Host Key Verification
    Configurable via SSH_HOST_KEY_POLICY in .env:
    - 'strict': RejectPolicy with known_hosts (RECOMMENDED FOR PRODUCTION)
    - 'warning': WarningPolicy with logs (development)
    - 'auto': AutoAddPolicy (INSECURE - local testing only)
    """
    ssh = paramiko.SSHClient()

    # VULN-003: Load host key policy from .env
    host_key_policy = current_app.config.get('SSH_HOST_KEY_POLICY', 'warning').lower()

    if host_key_policy == 'strict':
        # PRODUCTION: RejectPolicy with known_hosts
        known_hosts_path = current_app.config.get('SSH_KNOWN_HOSTS_PATH', os.path.expanduser('~/.ssh/known_hosts'))

        if os.path.exists(known_hosts_path):
            ssh.load_host_keys(known_hosts_path)
            current_app.logger.info(f'Loaded known_hosts from: {known_hosts_path}')
        else:
            current_app.logger.warning(f'known_hosts not found at: {known_hosts_path}')
            current_app.logger.warning('Create the file or change SSH_HOST_KEY_POLICY to "warning" in development')

        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        current_app.logger.info(f'SSH Host Key Policy: STRICT (RejectPolicy) - connections only to known hosts')

    elif host_key_policy == 'warning':
        # DEVELOPMENT: WarningPolicy with logs
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        current_app.logger.warning(f'SSH Host Key Policy: WARNING - host keys not verified (development only)')

    elif host_key_policy == 'auto':
        # INSECURE: AutoAddPolicy (testing only)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        current_app.logger.error(f'SSH Host Key Policy: AUTO (INSECURE) - vulnerable to MITM! Use only in local testing environment')

    else:
        raise ValueError(f'Invalid SSH_HOST_KEY_POLICY: {host_key_policy}. Use: strict, warning or auto')

    try:
        if server.auth_type == 'password':
            password = decrypt_credential(server.password)
            ssh.connect(
                hostname=server.host,
                port=server.port,
                username=server.username,
                password=password,
                timeout=30
            )
        else:
            # Use secure tempfile
            ssh_key_decrypted = decrypt_credential(server.ssh_key)
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as f:
                f.write(ssh_key_decrypted)
                key_file = f.name

            try:
                if os.name != 'nt':
                    os.chmod(key_file, 0o600)

                ssh.connect(
                    hostname=server.host,
                    port=server.port,
                    username=server.username,
                    key_filename=key_file,
                    timeout=30
                )
            finally:
                # ALWAYS clean up temporary file
                try:
                    os.unlink(key_file)
                except:
                    pass

        return ssh
    except Exception as e:
        raise Exception(f"Error connecting to server: {str(e)}")


def create_sftp_directory_recursive(sftp, remote_path):
    """
    Creates directories recursively via SFTP (without using shell commands)

    Args:
        sftp: Active SFTP client
        remote_path: Full path to create
    """
    parts = [p for p in remote_path.split('/') if p]
    current_path = ''
    for part in parts:
        current_path += '/' + part
        try:
            sftp.stat(current_path)
        except IOError:
            try:
                sftp.mkdir(current_path)
            except Exception:
                pass  # Directory may already exist in race condition


def get_directory_size(sftp, path):
    """Calculates the total size of a directory recursively"""
    total_size = 0
    files_count = 0

    try:
        # Ensure path always uses forward slashes for SFTP
        path = path.replace('\\', '/')
        for item in sftp.listdir_attr(path):
            # Use forward slash for remote paths (SFTP)
            item_path = f"{path.rstrip('/')}/{item.filename}"
            if item.st_mode & 0o040000:
                size, count = get_directory_size(sftp, item_path)
                total_size += size
                files_count += count
            else:
                total_size += item.st_size
                files_count += 1
    except Exception as e:
        print(f"Error processing {path}: {str(e)}")

    return total_size, files_count


def download_directory(sftp, remote_path, local_path):
    """Downloads a complete directory via SFTP"""
    try:
        os.makedirs(local_path, exist_ok=True)

        # Ensure remote_path always uses forward slashes for SFTP
        remote_path = remote_path.replace('\\', '/')

        for item in sftp.listdir_attr(remote_path):
            # Use forward slash for remote paths (SFTP)
            remote_item = f"{remote_path.rstrip('/')}/{item.filename}"
            local_item = os.path.join(local_path, item.filename)

            if item.st_mode & 0o040000:
                download_directory(sftp, remote_item, local_item)
            else:
                sftp.get(remote_item, local_item)

    except Exception as e:
        raise Exception(f"Error downloading directory: {str(e)}")
