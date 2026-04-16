"""
CyberQR Defense - Django Admin Configuration
==============================================
Registers ScanResult model with the admin panel.
Admin can view, search, and filter all scan history at /admin/
"""

from django.contrib import admin
from .models import ScanResult


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    """
    Customize how ScanResult records appear in the Django admin panel.
    """

    # Columns shown in the list view
    list_display = ('scanned_url', 'scan_type', 'risk_level', 'risk_score', 'scan_date')

    # Filter sidebar options
    list_filter = ('risk_level', 'scan_type', 'scan_date')

    # Search bar — searches inside these fields
    search_fields = ('scanned_url',)

    # Sort by newest scan by default
    ordering = ('-scan_date',)

    # Make these fields read-only (we don't want admins editing scan results)
    readonly_fields = ('scanned_url', 'scan_type', 'risk_level', 'risk_score', 'scan_date')
