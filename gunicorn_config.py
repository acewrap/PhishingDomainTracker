import multiprocessing
import os

bind = "0.0.0.0:8080"

try:
    workers = multiprocessing.cpu_count() * 2 + 1
except NotImplementedError:
    workers = 3

threads = 2
worker_class = 'gthread'

# Ensure logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')

# Logging Configuration
loglevel = "info"

logconfig_dict = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'generic': {
            'format': '%(asctime)s [%(process)d] [%(levelname)s] %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
            'class': 'logging.Formatter',
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'generic',
            'stream': 'ext://sys.stdout',
        },
        'file': {
            'class': 'logging.FileHandler',
            'formatter': 'generic',
            'filename': 'logs/gunicorn.log',
        },
    },
    'loggers': {
        'gunicorn.error': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False,
            'qualname': 'gunicorn.error'
        },
        'gunicorn.access': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False,
            'qualname': 'gunicorn.access'
        },
    }
}
