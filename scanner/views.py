"""
CyberQR Defense - Views
=========================
Handles homepage and scan requests.
"""

import os
import tempfile
from django.shortcuts import render, redirect
from django.utils import timezone
from .models import ScanResult
from .detector import analyze_url, decode_qr_code, get_security_recommendations


def home(request):
    return render(request, 'scanner/home.html')


def scan(request):
    if request.method != 'POST':
        return redirect('home')

    url = None
    scan_type = 'URL'
    qr_decode_status = None

    qr_image = request.FILES.get('qr_image')
    manual_url = request.POST.get('url', '').strip()

    if qr_image:
        scan_type = 'QR'
        suffix = os.path.splitext(qr_image.name)[1] or '.png'
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            for chunk in qr_image.chunks():
                tmp_file.write(chunk)
            tmp_path = tmp_file.name

        decoded_text = decode_qr_code(tmp_path)
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

        if decoded_text:
            url = decoded_text
            qr_decode_status = f"QR decoded: {decoded_text[:80]}..."
        else:
            return render(request, 'scanner/home.html', {'error': "Could not decode QR code. Make sure the image is clear."})

    elif manual_url:
        url = manual_url
        if not url.startswith(('http://', 'https://', 'upi://')):
            url = 'https://' + url
    else:
        return render(request, 'scanner/home.html', {'error': "Please provide a URL or QR image."})

    # Analyze
    analysis = analyze_url(url)

    # Recommendations
    recommendations = get_security_recommendations(
        analysis['risk_level'],
        analysis['checks']
    )

    # Save to DB (optional)
    try:
        ScanResult.objects.create(
            scanned_url=url[:2000],
            scan_type=scan_type,
            risk_level=analysis['risk_level'],
            risk_score=analysis['risk_score'],
        )
    except Exception:
        pass

    context = {
        'url'             : url,
        'scan_type'       : scan_type,
        'risk_level'      : analysis['risk_level'],
        'risk_score'      : analysis['risk_score'],
        'checks'          : analysis['checks'],
        'domain_info'     : analysis['domain_info'],
        'logs'            : analysis['logs'],
        'recommendations' : recommendations,
        'upi_detected'    : analysis['upi_detected'],
        'qr_decode_status': qr_decode_status,
        'scan_time'       : timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'risk_score_pct'  : analysis['risk_score'],
    }

    return render(request, 'scanner/result.html', context)