<h1 align="center">SPECTRE - Automated Backup Management System</h1>

<p align="center">
  <img src="docs/images/logo.png" alt="Spectre Logo" width="200"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/Flask-3.0-green.svg" alt="Flask 3.0"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License"/>
  <img src="https://img.shields.io/badge/Security-AES--256-red.svg" alt="AES-256"/>
</p>

---

## Overview

**Spectre** is a professional automated backup management system designed for centralized remote server backup orchestration via SSH/SFTP. Architected with production security standards, it implements AES-256 encryption, multi-factor authentication, role-based access control, and comprehensive audit trails for mission-critical data protection.

![Dashboard](docs/images/dashboard.png)

## Key Features

### Security Architecture
- **AES-256 Encryption** - Military-grade encryption for backup archives with password protection
- **Multi-Factor Authentication** - TOTP implementation supporting industry-standard authenticators (Google Authenticator, Authy)
- **Credential Protection** - Fernet-based encryption for all server credentials and SSH private keys
- **PBKDF2-SHA256 Password Hashing** - 600,000 iterations compliant with OWASP 2023 recommendations
- **Comprehensive Audit Trail** - Immutable logging of all authentication events and system operations
- **TLS/SSL Enforcement** - Native Let's Encrypt integration with automatic certificate management

### Backup Operations
- **Automated Scheduling Engine** - Cron-based execution with daily, weekly, and on-demand triggers
- **Intelligent Retention Management** - Policy-driven lifecycle management with automatic cleanup
- **One-Click Recovery** - Direct restoration to origin servers with integrity verification
- **Real-Time Monitoring Dashboard** - Live status tracking with resource utilization metrics
- **Multi-Server Architecture** - Concurrent management of distributed server infrastructure
- **Geographic Replication** - Automated cross-server replication for disaster recovery scenarios
- **Asynchronous Notifications** - Telegram integration for operational alerts and status updates ([Setup Guide](TELEGRAM_SETUP.md))

### Multi-User System
- **Role-Based Access Control** - Hierarchical permission model with administrative and standard user roles
- **Data Isolation** - Complete resource segregation ensuring users only access their own data
- **User Lifecycle Management** - Full user provisioning and de-provisioning with audit compliance
- **Per-User Encryption** - Cryptographically unique backup encryption keys for each user account

## Technical Architecture

- **Application Framework**: Flask 3.0 with SQLAlchemy ORM and Flask-Login session management
- **Cryptographic Stack**: Python cryptography library (Fernet), PyOTP for TOTP, pyzipper for encrypted archives
- **Remote Connectivity**: Paramiko SSH/SFTP client with connection pooling
- **Task Orchestration**: APScheduler with CronTrigger-based job scheduling
- **Notification System**: python-telegram-bot with async/await patterns
- **Production Stack**: Gunicorn WSGI server, Nginx reverse proxy, systemd process supervision, Fail2Ban intrusion prevention
- **Data Persistence**: SQLite with PostgreSQL/MySQL migration compatibility

## Quick Start

### Prerequisites
- Python 3.10+
- Ubuntu 20.04+ or Debian 11+ (for production deployment)
- SSH access to remote servers

### Development Installation

```bash
# Clone repository
git clone https://github.com/syrusnfs/Spectre.git
cd Spectre

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Generate encryption keys
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env
python3 -c "from cryptography.fernet import Fernet; print('ENCRYPTION_KEY=' + Fernet.generate_key().decode())" >> .env

# Initialize database
python3 wsgi.py

Access the application at `http://localhost:5000`
```


## Production Deployment

Spectre includes an automated installation script for production deployments:

```bash
# Run as root
sudo ./install.sh
```

The installer will:
- Install system dependencies (Python, Nginx, Certbot, Fail2Ban)
- Configure SSL certificates (Let's Encrypt or self-signed)
- Set up Nginx reverse proxy with security headers
- Create systemd service with auto-restart
- Configure Fail2Ban for brute-force protection
- Initialize database and create admin user

**Post-Installation Steps:**
- Access the application via `https://your-domain.com`
- Enable two-factor authentication for enhanced security (recommended)
- Configure backup retention policies based on your requirements
- Register remote servers and define backup routines
- Set up Telegram notifications for real-time operational alerts (optional)

## Usage

### 1. Server Registration
Register remote servers with SSH credentials supporting both password and key-based authentication methods.

![Servers Management](docs/images/servers.png)

### 2. Backup Routine Configuration
Define backup targets, scheduling parameters, and data retention policies.

![Routines](docs/images/routines.png)

### 3. Monitoring and Recovery
Monitor backup execution status in real-time and perform one-click restoration operations.

![Backups](docs/images/backups.png)

### 4. Notification Configuration (Optional)
Configure Telegram integration to receive real-time alerts for backup operations, system events, and critical status changes. Refer to [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md) for detailed configuration instructions.

### 5. Backup Replication Configuration
Enable automatic replication of backup archives to secondary storage locations for enhanced data redundancy and disaster recovery capabilities.

## Security Implementation

- **Input Validation** - Comprehensive sanitization and validation for all user-supplied data
- **Path Traversal Prevention** - Secure file path validation preventing directory traversal attacks
- **Authorization Enforcement** - Strict authorization checks preventing insecure direct object references
- **Session Management** - Automatic session regeneration with secure, HTTP-only cookie implementation
- **Timing Attack Mitigation** - Constant-time comparison operations for sensitive data
- **Transport Security** - Enforced HTTPS with automatic HTTP-to-HTTPS redirection
- **Security Headers** - Comprehensive security headers including CSP, HSTS, X-Frame-Options, and X-Content-Type-Options
- **Credential Protection** - AES-256 encryption for Telegram API credentials with integrity validation

## System Requirements

### Minimum Specifications
- 2 CPU cores
- 2GB RAM
- 20GB system storage (excluding backup data storage)

### Recommended Specifications
- 4 CPU cores
- 4GB RAM
- SSD-based storage for database operations
- Dedicated storage volume for backup archives

## Contributing

Contributions to this project are welcome. Please submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="left">
  Made by Syrus
</p>

