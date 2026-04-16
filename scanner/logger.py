"""
CyberQR Defense - Custom Logging Utilities
==========================================
Utility functions for consistent logging across the application.
Logs visitor IP, user agent, timestamps, and scan details.
"""

import logging
from django.conf import settings
from django.utils import timezone


# Get the main application logger
logger = logging.getLogger('cyberqr_access')


def log_visit(request, message=""):
    """
    Log a website visit with IP and user agent.
    
    Args:
        request: Django HttpRequest
        message: Additional context (e.g. "homepage visit")
    """
    ip = request.META.get('REMOTE_ADDR', 'unknown')
    ua = request.META.get('HTTP_USER_AGENT', 'unknown')[:200]  # Truncate long UAs
    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    logger.info(f"VISIT|IP:{ip}|UA:{ua[:50]}...|MSG:{message}|TS:{timestamp}")


def log_scan(request, scanned_url, risk_score, scan_type, risk_level):
    """
    Log a phishing scan result.
    
    Args:
        request: Django HttpRequest
        scanned_url: The analyzed URL
        risk_score: 0-100 risk score
        scan_type: 'QR' or 'URL'
        risk_level: 'SAFE'/'SUSPICIOUS'/'HIGH RISK'
    """
    ip = request.META.get('REMOTE_ADDR', 'unknown')
    ua = request.META.get('HTTP_USER_AGENT', 'unknown')[:200]
    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    url_preview = scanned_url[:100] + "..." if len(scanned_url) > 100 else scanned_url
    
    logger.warning(
        f"SCAN|IP:{ip}|UA:{ua[:50]}...|URL:{url_preview}|"
        f"RISK:{risk_score}/{risk_level}|TYPE:{scan_type}|TS:{timestamp}"
    )


def log_error(request, error_msg):
    """
    Log application errors.
    
    Args:
        request: Django HttpRequest  
        error_msg: Error description
    """
    ip = request.META.get('REMOTE_ADDR', 'unknown')
    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    logger.error(f"ERROR|IP:{ip}|MSG:{error_msg}|TS:{timestamp}")
