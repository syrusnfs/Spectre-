#!/bin/bash
#
# Spectre - Production Deployment: Nginx, Gunicorn, Systemd, Fail2Ban and SSL
#

set -e 

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

APP_DIR="/opt/spectre"
APP_USER="spectre"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

USE_LETSENCRYPT=false
SSL_EMAIL=""
SERVER_HOSTNAME=""
FLASK_PORT=5000
BACKUP_PATH=""
ADMIN_USER=""
ADMIN_EMAIL=""
ADMIN_PASS=""

print_banner() {
    echo ""
    echo "================================="
    echo "  SPECTRE - AUTO DEPLOY"
    echo "================================="
    echo ""
}

print_step() {
    echo -e "${BLUE}[$1]${NC} $2"
}

print_success() {
    echo -e "  ${GREEN}$1${NC}"
}

print_warning() {
    echo -e "  ${YELLOW}$1${NC}"
}

print_error() {
    echo -e "  ${RED}$1${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run with sudo."
        echo "  Usage: sudo ./install.sh"
        exit 1
    fi
}

check_os() {
    print_step "1/10" "Checking operating system..."

    if [ ! -f /etc/os-release ]; then
        print_error "Unsupported system."
        exit 1
    fi

    . /etc/os-release

    if [ "$ID" != "ubuntu" ] && [ "$ID" != "debian" ]; then
        print_error "Only Ubuntu/Debian are supported."
        exit 1
    fi

    print_success "System detected: $PRETTY_NAME"
}

install_system_deps() {
    print_step "2/10" "Installing system dependencies..."

    export DEBIAN_FRONTEND=noninteractive

    apt-get update -qq
    apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        python3-full \
        nginx \
        fail2ban \
        rsync \
        openssl \
        certbot \
        python3-certbot-nginx \
        > /dev/null 2>&1

    print_success "System dependencies installed."
}

interactive_config() {
    print_step "3/10" "Application configuration..."
    echo ""
    echo "================="
    echo "  CONFIGURATION"
    echo "================="

    echo ""
    read -p "  Internal Flask Port (Default: 5000): " FLASK_PORT
    FLASK_PORT=${FLASK_PORT:-5000}

    echo ""
    echo "  SSL certificate configuration:"
    echo "  1) Let's Encrypt (requires FQDN and exposed ports to external network: 80/443)"
    echo "  2) Self-signed (For LAN use, accepts internal IP or FQDN)"
    echo ""
    read -p "  Choose [1-2] (default: 2): " SSL_TYPE
    SSL_TYPE=${SSL_TYPE:-2}

    case "$SSL_TYPE" in
        1)
            USE_LETSENCRYPT=true
            echo ""
            echo "  Public domain (must point to this server)."
            echo "  Example: spectre.example.com"
            read -p "  Domain: " SERVER_HOSTNAME
            while [ -z "$SERVER_HOSTNAME" ]; do
                print_error "Domain cannot be blank."
                read -p "  Domain: " SERVER_HOSTNAME
            done

            echo ""
            echo "  Email for Let's Encrypt notifications."
            read -p "  Email: " SSL_EMAIL
            while [ -z "$SSL_EMAIL" ]; do
                print_error "Email cannot be blank."
                read -p "  Email: " SSL_EMAIL
            done
            ;;
        2)
            USE_LETSENCRYPT=false
            echo ""
            echo "  Do you want to configure a custom internal hostname/domain?"
            echo "  If not, the server's IP address will be used automatically."
            read -p "  Use custom hostname/domain? (y/N): " USE_CUSTOM_HOSTNAME

            case "$USE_CUSTOM_HOSTNAME" in
                [Yy]|[Yy][Ee][Ss])
                    echo ""
                    echo "  Internal hostname or domain."
                    echo "  Example: spectre-server.local or spectre.company.lan"
                    read -p "  Hostname: " SERVER_HOSTNAME
                    while [ -z "$SERVER_HOSTNAME" ]; do
                        print_error "Hostname cannot be blank."
                        read -p "  Hostname: " SERVER_HOSTNAME
                    done
                    ;;
                *)
                    SERVER_HOSTNAME=$(hostname -I | awk '{print $1}')
                    if [ -z "$SERVER_HOSTNAME" ]; then
                        print_error "Unable to detect IP automatically."
                        read -p "  Enter IP manually: " SERVER_HOSTNAME
                    else
                        echo "  IP detected automatically: $SERVER_HOSTNAME"
                    fi
                    ;;
            esac
            ;;
        *)
            print_error "Invalid option. Using self-signed certificate by default."
            USE_LETSENCRYPT=false
            SERVER_HOSTNAME=$(hostname -I | awk '{print $1}')
            if [ -z "$SERVER_HOSTNAME" ]; then
                print_error "Unable to detect IP automatically."
                read -p "  Enter IP manually: " SERVER_HOSTNAME
            else
                echo "  IP detected automatically: $SERVER_HOSTNAME"
            fi
            ;;
    esac

    echo ""
    echo "  Directory where backups will be stored."
    read -p "  Path (default: /opt/backups): " BACKUP_PATH
    BACKUP_PATH=${BACKUP_PATH:-/opt/backups}

    echo ""
    echo "  Administrator user credentials:"
    read -p "  Username: " ADMIN_USER
    while [ -z "$ADMIN_USER" ]; do
        print_error "Username cannot be blank."
        read -p "  Username: " ADMIN_USER
    done

    read -p "  Email: " ADMIN_EMAIL
    while [ -z "$ADMIN_EMAIL" ]; do
        print_error "Email cannot be blank."
        read -p "  Email: " ADMIN_EMAIL
    done

    read -s -p "  Password: " ADMIN_PASS
    echo ""
    while [ -z "$ADMIN_PASS" ]; do
        print_error "Password cannot be blank."
        read -s -p "  Password: " ADMIN_PASS
        echo ""
    done

    read -s -p "  Confirm password: " ADMIN_PASS_CONFIRM
    echo ""
    while [ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]; do
        print_error "Passwords do not match."
        read -s -p "  Password: " ADMIN_PASS
        echo ""
        read -s -p "  Confirm password: " ADMIN_PASS_CONFIRM
        echo ""
    done

    echo ""
    echo "==========="
    echo "  SUMMARY"
    echo "==========="
    echo "  Application (internal):  127.0.0.1:$FLASK_PORT"
    echo "  Nginx HTTPS:             https://$SERVER_HOSTNAME (port 443)"
    echo "  Nginx HTTP:              http://$SERVER_HOSTNAME (port 80 → redirects to HTTPS)"
    echo "  Backup directory:        $BACKUP_PATH"
    echo "  Administrator:           $ADMIN_USER"
    echo "  Administrator email:     $ADMIN_EMAIL"
    if [ "$USE_LETSENCRYPT" = true ]; then
        echo "  SSL certificate:         Let's Encrypt (automatic, scheduled renewal)"
    else
        echo "  SSL certificate:         Self-signed (valid for 10 years)"
    fi
    echo "==========="
    echo ""

    read -p "  Do you want to continue? (Y/n): " CONFIRM
    case "$CONFIRM" in
        [Nn])
            print_warning "Installation cancelled by user."
            exit 0
            ;;
        *)
            ;;
    esac

    print_success "Configuration completed."
}

create_system_user() {
    print_step "4/10" "Creating system user..."

    if id "$APP_USER" >/dev/null 2>&1; then
        print_warning "User '$APP_USER' already exists."
    else
        useradd --system --no-create-home --shell /bin/false "$APP_USER"
        print_success "User '$APP_USER' created."
    fi
}

deploy_application() {
    print_step "5/10" "Deploying application to $APP_DIR..."

    mkdir -p "$APP_DIR"

    rsync -a \
        --exclude='venv' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='.git' \
        --exclude='instance' \
        --exclude='backups' \
        --exclude='*.old' \
        "$SCRIPT_DIR/" "$APP_DIR/"

    print_success "Application copied to $APP_DIR."
}

create_env_file() {
    print_step "6/10" "Creating .env configuration file..."

    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

    cat > "$APP_DIR/.env" << EOF
# Spectre - Production

# SECURITY
SECRET_KEY=$SECRET_KEY
ENCRYPTION_KEY=$ENCRYPTION_KEY
PASSWORD_HASH_METHOD=pbkdf2:sha256:600000

# SSH SECURITY
SSH_HOST_KEY_POLICY=strict
SSH_KNOWN_HOSTS_PATH=~/.ssh/known_hosts

# FLASK
FLASK_ENV=production
FLASK_DEBUG=False
FLASK_HOST=127.0.0.1
FLASK_PORT=$FLASK_PORT

# SERVER
SERVER_HOSTNAME=$SERVER_HOSTNAME

# DATABASE
DATABASE_URI=sqlite:///$APP_DIR/instance/backups.db

# BACKUPS
BACKUP_BASE_PATH=$BACKUP_PATH

# GUNICORN
GUNICORN_WORKERS=3
GUNICORN_ACCESS_LOG=/var/log/spectre/access.log
GUNICORN_ERROR_LOG=/var/log/spectre/error.log
EOF

    chmod 600 "$APP_DIR/.env"
    print_success ".env file created."
}

setup_python() {
    print_step "7/10" "Configuring Python environment and dependencies..."

    cd "$APP_DIR"

    python3 -m venv venv

    . venv/bin/activate
    pip install --upgrade pip --quiet
    pip install -r requirements.txt --quiet
    deactivate

    mkdir -p "$APP_DIR/instance"
    mkdir -p "$BACKUP_PATH"
    mkdir -p /var/log/spectre

    . venv/bin/activate
    export SKIP_SCHEDULER='True'
    python3 << EOF
import sys
sys.path.insert(0, '$APP_DIR')

from dotenv import load_dotenv
load_dotenv('$APP_DIR/.env')

from wsgi import app
from app.extensions import db
from app.models import User
from app.security import hash_password, generate_backup_password
from app.security.encryption import encrypt_credential

with app.app_context():
    db.create_all()

    if not User.query.first():
        backup_pwd = generate_backup_password()
        encrypted_backup_pwd = encrypt_credential(backup_pwd)

        user = User(
            username='$ADMIN_USER',
            email='$ADMIN_EMAIL',
            password_hash=hash_password('$ADMIN_PASS'),
            backup_password=encrypted_backup_pwd,
            role='admin'
        )
        db.session.add(user)
        db.session.commit()
        print('Administrator user created.')
EOF
    unset SKIP_SCHEDULER
    deactivate

    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    chown -R "$APP_USER:$APP_USER" "$BACKUP_PATH"
    chown -R "$APP_USER:$APP_USER" /var/log/spectre

    print_success "Python configured and database initialized."
}

setup_nginx() {
    print_step "8/10" "Configuring Nginx with HTTPS..."

    if nginx -V 2>&1 | grep -q "headers-more"; then
        HEADERS_MORE="    more_clear_headers 'Server';
    more_clear_headers 'X-Powered-By';"
    else
        HEADERS_MORE=""
    fi

    rm -f /etc/nginx/sites-enabled/default || true

    if [ "$USE_LETSENCRYPT" = true ]; then
        cat > /etc/nginx/sites-available/spectre << EOF
server {
    listen 80;
    server_name $SERVER_HOSTNAME;

    client_max_body_size 100M;
    client_body_timeout 300s;

    access_log /var/log/nginx/spectre-access.log;
    error_log /var/log/nginx/spectre-error.log;

    location / {
        proxy_pass http://127.0.0.1:$FLASK_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;

        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    location /static {
        alias $APP_DIR/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

        ln -sf /etc/nginx/sites-available/spectre /etc/nginx/sites-enabled/spectre

        nginx -t
        systemctl restart nginx
        systemctl enable nginx

        certbot --nginx \
            --non-interactive \
            --agree-tos \
            --redirect \
            -m "$SSL_EMAIL" \
            -d "$SERVER_HOSTNAME" || {
                print_error "Failed to obtain Let's Encrypt certificate. Check DNS and ports 80/443."
                exit 1
            }

        if ! grep -q "Strict-Transport-Security" /etc/nginx/sites-available/spectre; then
            sed -i "/ssl_certificate_key/a \
    # Security headers\n\
    server_tokens off;\n\
$HEADERS_MORE\n\
    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\
    add_header X-Frame-Options \"DENY\" always;\n\
    add_header X-Content-Type-Options \"nosniff\" always;\n\
    add_header X-XSS-Protection \"1; mode=block\" always;\n" /etc/nginx/sites-available/spectre
        fi

        nginx -t
        systemctl reload nginx

        print_success "Nginx configured with Let's Encrypt (HTTPS active)."
    else
        mkdir -p /etc/nginx/ssl

        openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
            -keyout /etc/nginx/ssl/spectre.key \
            -out /etc/nginx/ssl/spectre.crt \
            -subj "/C=US/ST=State/L=City/O=Spectre/CN=$SERVER_HOSTNAME" \
            > /dev/null 2>&1

        chmod 600 /etc/nginx/ssl/spectre.key
        chmod 644 /etc/nginx/ssl/spectre.crt

        cat > /etc/nginx/sites-available/spectre << EOF
# Spectre - Nginx + Gunicorn (Self-Signed HTTPS)

# HTTP → HTTPS (redirect)
server {
    listen 80;
    server_name $SERVER_HOSTNAME;

    return 301 https://\$server_name\$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name $SERVER_HOSTNAME;

    # SSL Certificate
    ssl_certificate /etc/nginx/ssl/spectre.crt;
    ssl_certificate_key /etc/nginx/ssl/spectre.key;

    # SSL Parameters (recommended intermediate level)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    server_tokens off;
$HEADERS_MORE
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    client_max_body_size 100M;
    client_body_timeout 300s;

    access_log /var/log/nginx/spectre-access.log;
    error_log /var/log/nginx/spectre-error.log;

    location / {
        proxy_pass http://127.0.0.1:$FLASK_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;

        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    location /static {
        alias $APP_DIR/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

        ln -sf /etc/nginx/sites-available/spectre /etc/nginx/sites-enabled/spectre

        nginx -t
        systemctl restart nginx
        systemctl enable nginx

        print_success "Nginx configured with self-signed certificate."
    fi
}

setup_fail2ban() {
    print_step "9/10" "Configuring Fail2Ban..."

    cat > /etc/fail2ban/jail.d/spectre.conf << 'EOF'
[spectre-auth]
enabled = true
port = http,https
filter = spectre-auth
logpath = /var/log/nginx/spectre-access.log
maxretry = 10
findtime = 60
bantime = 3600
EOF

    cat > /etc/fail2ban/filter.d/spectre-auth.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "POST /auth/login HTTP.*" (401|403)
            ^<HOST> .* "POST /auth/verify_otp HTTP.*" (401|403)
ignoreregex =
EOF

    systemctl restart fail2ban
    systemctl enable fail2ban

    print_success "Fail2Ban configured (10 attempts in 60 seconds, 60 minute ban)."
}

setup_systemd() {
    print_step "10/10" "Creating systemd service..."

    cat > /etc/systemd/system/spectre.service << EOF
[Unit]
Description=Spectre (Gunicorn)
After=network.target

[Service]
Type=notify
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"

ExecStart=$APP_DIR/venv/bin/gunicorn -c gunicorn.conf.py wsgi:app

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$BACKUP_PATH $APP_DIR/instance /var/log/spectre

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable spectre
    systemctl start spectre

    sleep 2

    if systemctl is-active --quiet spectre; then
        print_success "Spectre service created and started."
    else
        print_error "Error starting spectre service."
        systemctl status spectre --no-pager
        exit 1
    fi
}

show_summary() {
    echo ""
    echo "======================================================================"
    echo                       "INSTALLATION COMPLETE"
    echo "======================================================================"
    echo ""
    echo "  Application location:            $APP_DIR"
    echo "  System user:                     $APP_USER"
    echo "  Database:                        $APP_DIR/instance/backups.db"
    echo "  Backup directory:                $BACKUP_PATH"

    if [ "$USE_LETSENCRYPT" = true ]; then
        echo "  SSL certificate:                 Let's Encrypt"
        echo "    Path: /etc/letsencrypt/live/$SERVER_HOSTNAME/"
        echo "    Automatic renewal configured (Certbot)."
    else
        echo "  SSL certificate:                 Self-signed"
        echo "    Path: /etc/nginx/ssl/spectre.crt"
        echo "    Certificate valid for 10 years."
    fi

    echo ""
    echo "  HTTPS URL:                       https://$SERVER_HOSTNAME"
    echo "  HTTP URL:                        http://$SERVER_HOSTNAME (redirects to HTTPS)"
    echo ""
    echo "  Initial credentials:"
    echo "    Username:                      $ADMIN_USER"
    echo "    Email:                         $ADMIN_EMAIL"
    echo "    Password:                      (as set during installation)"
    echo ""

    if [ "$USE_LETSENCRYPT" = false ]; then
        echo "  Warning:"
        echo "    A self-signed certificate is being used."
        echo "    Your browser may display a security warning."
        echo "    This is appropriate for internal network use."
    fi

    echo ""
    echo "======================================================================"
    echo                         "USEFUL COMMANDS"
    echo "======================================================================"
    echo "  View service status:      sudo systemctl status spectre"
    echo "  Stop service:             sudo systemctl stop spectre"
    echo "  Start service:            sudo systemctl start spectre"
    echo "  Restart service:          sudo systemctl restart spectre"
    echo "  View application logs:    sudo journalctl -u spectre -f"
    echo "======================================================================"
    echo ""
    echo "  NEXT STEPS:"
    echo "  1. Access the web interface using the URL above."
    echo "  2. Log in with the configured credentials."
    echo "  3. Enable two-factor authentication (2FA) in user settings."
    echo "  4. Configure servers and backup routines."
    echo "======================================================================"
    echo ""
}

# MAIN
main() {
    print_banner
    check_root
    check_os
    install_system_deps
    interactive_config
    create_system_user
    deploy_application
    create_env_file
    setup_python
    setup_nginx
    setup_fail2ban
    setup_systemd
    show_summary
}

main "$@"
