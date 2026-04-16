"""
CyberQR Defense - Scanner App URL Patterns
============================================
URL routes for the scanner application.

Routes:
    /       → home view  (Homepage with upload form)
    /scan/  → scan view  (POST: process QR or URL)
"""

from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),      # Homepage
    path('scan/', views.scan, name='scan'), # Scan endpoint (POST)
]
