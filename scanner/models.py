"""
CyberQR Defense - Database Models
===================================
Defines the ScanResult model to store every phishing scan in the database.
Admin can view all historical scans via the Django admin panel.
"""

from django.db import models


class ScanResult(models.Model):
    """
    Stores the result of each QR code or URL phishing scan.

    Fields:
        scanned_url  - The URL that was analyzed
        scan_type    - Either 'QR' (from image upload) or 'URL' (manually pasted)
        risk_level   - 'SAFE', 'SUSPICIOUS', or 'HIGH RISK'
        risk_score   - Numeric score from 0 to 100
        scan_date    - Timestamp when the scan was performed
    """

    # The three possible risk levels
    RISK_CHOICES = [
        ('SAFE', 'Safe'),
        ('SUSPICIOUS', 'Suspicious'),
        ('HIGH RISK', 'High Risk'),
    ]

    # The two scan types
    SCAN_TYPE_CHOICES = [
        ('QR', 'QR Code'),
        ('URL', 'Manual URL'),
    ]

    scanned_url = models.URLField(max_length=2000, verbose_name="Scanned URL")
    scan_type   = models.CharField(max_length=10, choices=SCAN_TYPE_CHOICES, verbose_name="Scan Type")
    risk_level  = models.CharField(max_length=20, choices=RISK_CHOICES, verbose_name="Risk Level")
    risk_score  = models.IntegerField(verbose_name="Risk Score (0–100)")
    scan_date   = models.DateTimeField(auto_now_add=True, verbose_name="Scan Date")

    class Meta:
        ordering = ['-scan_date']           # Newest scans appear first
        verbose_name = "Scan Result"
        verbose_name_plural = "Scan Results"

    def __str__(self):
        return f"[{self.scan_type}] {self.scanned_url[:60]} → {self.risk_level} ({self.risk_score}/100)"
