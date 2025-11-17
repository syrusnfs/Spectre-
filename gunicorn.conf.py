"""
Gunicorn Configuration File
Production-ready configuration for Spectre

Usage:
    gunicorn -c gunicorn.conf.py wsgi:app
"""
import os
import multiprocessing

# Server socket
bind = f"{os.getenv('FLASK_HOST', '0.0.0.0')}:{os.getenv('FLASK_PORT', '5000')}"
backlog = 2048

# Worker processes
workers = int(os.getenv('GUNICORN_WORKERS', multiprocessing.cpu_count() * 2 + 1))
worker_class = 'sync'
worker_connections = 1000
timeout = 120
keepalive = 5

# Maximum requests per worker (helps prevent memory leaks)
max_requests = 1000
max_requests_jitter = 50

# Process naming
proc_name = 'spectre'

# Daemon mode
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Logging
accesslog = os.getenv('GUNICORN_ACCESS_LOG', '-')  # '-' for stdout
errorlog = os.getenv('GUNICORN_ERROR_LOG', '-')    # '-' for stderr
loglevel = os.getenv('GUNICORN_LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Server mechanics
preload_app = False  # Set to True to load app before forking workers (saves memory but can cause issues with some apps)
sendfile = None
reuse_port = False
chdir = os.getcwd()

# SSL (if needed)
# keyfile = '/path/to/keyfile'
# certfile = '/path/to/certfile'

# Hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    print("\n" + "="*70)
    print("  SPECTRE - Starting Gunicorn Server")
    print("="*70)
    print(f"  Workers: {workers}")
    print(f"  Binding: {bind}")
    print(f"  Timeout: {timeout}s")
    print("="*70 + "\n")


def on_reload(server):
    """Called to recycle workers during a reload via SIGHUP."""
    pass


def when_ready(server):
    """Called just after the server is started."""
    print(f"\n✓ Server is ready. Listening on {bind}\n")


def worker_int(worker):
    """Called when a worker receives the SIGINT or SIGQUIT signal."""
    pass


def worker_abort(worker):
    """Called when a worker receives the SIGABRT signal."""
    pass
