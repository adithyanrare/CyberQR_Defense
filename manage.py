#!/usr/bin/env python
"""
CyberQR Defense — Django Management Script
============================================
Run this file to interact with the Django project:
    python manage.py runserver     ← Start development server
    python manage.py makemigrations ← Create database migrations
    python manage.py migrate        ← Apply migrations
    python manage.py createsuperuser ← Create admin user
"""

import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberqr.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
