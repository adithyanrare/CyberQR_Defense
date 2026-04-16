"""
CyberQR Defense - Main URL Configuration
==========================================
Routes all requests to the scanner app.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # Django admin panel — accessible at /admin/
    path('admin/', admin.site.urls),

    # Include scanner app URLs — all scanner routes start from root '/'
    path('', include('scanner.urls')),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
# ↑ This line serves uploaded QR images during development
