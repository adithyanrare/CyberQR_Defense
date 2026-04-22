

import re
import socket
from urllib.parse import urlparse, parse_qs


# ─── Suspicious Keywords ───────────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'bank', 'account', 'confirm',
    'password', 'signin', 'wallet', 'paypal', 'phishing', 'free', 'prize',
    'winner', 'support', 'recovery', 'authenticate', 'security', 'alert',
]

# ─── URL Shorteners (common in phishing) ───────────────────────────────────────
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'shorturl.at',
    'shorte.st', 'rebrand.ly', 'buff.ly', 'linktr.ee', 'urlshortener'
]

# ─── Suspicious TLDs (often used in phishing) ──────────────────────────────────
SUSPICIOUS_TLDS = ['.xyz', '.top', '.cf', '.tk', '.ml', '.ga', '.ru', '.cn', '.pw']

# ─── UPI Parameters ────────────────────────────────────────────────────────────
UPI_PARAMS = ['pa', 'pn', 'am', 'cu', 'tn']


def analyze_url(url: str) -> dict:
    """
    Main phishing analysis function with improved sensitivity.
    """
    result = {
        'url'         : url,
        'risk_score'  : 0,
        'risk_level'  : 'SAFE',
        'checks'      : [],
        'domain_info' : {},
        'logs'        : [],
        'upi_detected': False,
    }

    logs = result['logs']
    checks = result['checks']

    logs.append("Initializing CyberQR Defense scanner (improved version)...")
    logs.append(f"Target URL: {url[:80]}{'...' if len(url) > 80 else ''}")
    logs.append("Starting rule-based phishing analysis...")

    # ── Parse the URL ─────────────────────────────────────────────────────────
    try:
        parsed = urlparse(url)
        scheme    = parsed.scheme.lower()
        netloc    = parsed.netloc.lower()
        path      = parsed.path
        query_str = parsed.query
    except Exception:
        result['risk_score'] = 90
        result['risk_level'] = 'HIGH RISK'
        logs.append("[ERROR] Could not parse URL — marked HIGH RISK")
        return result

    # ── Improved domain extraction ────────────────────────────────────────────
    hostname = netloc.split(':')[0]  # Remove port
    parts = hostname.split('.')

    if len(parts) >= 2:
        domain = parts[-2] + '.' + parts[-1]
        tld = '.' + parts[-1]
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    else:
        domain = hostname
        tld = ''
        subdomain = ''

    # Fallback for better domain handling
    if len(domain) < 4 and len(parts) > 2:
        domain = parts[-3] + '.' + parts[-2] + '.' + parts[-1]

    result['domain_info'] = {
        'full_url'  : url,
        'hostname'  : hostname,
        'domain'    : domain,
        'tld'       : tld,
        'subdomain' : subdomain,
        'protocol'  : scheme,
        'url_length': len(url),
    }

    logs.append(f"Domain extracted: {domain} | TLD: {tld}")
    logs.append(f"Protocol: {scheme.upper()} | Subdomain: {subdomain or 'None'}")

    score = 0

    # ══════════════════════════════════════════════════════════════════════════
    # RULE 1: IP Address in URL (Very strong signal)
    # ══════════════════════════════════════════════════════════════════════════
    logs.append("Checking for IP address...")
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    is_ip = bool(ip_pattern.search(hostname))

    if is_ip:
        score += 40
        checks.append({
            'feature': 'IP Address in URL',
            'result': hostname,
            'risk': 'DANGEROUS',
            'icon': '✖',
            'description': 'Raw IP address used — highly suspicious for phishing.',
        })
        logs.append(f"[ALERT] IP address detected (+40 points)")
    else:
        checks.append({'feature': 'IP Address in URL', 'result': 'No IP', 'risk': 'SAFE', 'icon': '✔', 'description': 'Proper domain name used.'})
        logs.append("IP check: SAFE")

    # ══════════════════════════════════════════════════════════════════════════
    # RULE 2: HTTPS Check
    # ══════════════════════════════════════════════════════════════════════════
    logs.append("Checking HTTPS status...")
    if scheme == 'http':
        score += 25
        checks.append({'feature': 'HTTPS Status', 'result': 'HTTP', 'risk': 'SUSPICIOUS', 'icon': '⚠', 'description': 'No encryption — dangerous for login/payment pages.'})
        logs.append("[WARNING] HTTP detected (+25 points)")
    elif scheme == 'https':
        checks.append({'feature': 'HTTPS Status', 'result': 'HTTPS', 'risk': 'SAFE', 'icon': '✔', 'description': 'Encrypted connection.'})
        logs.append("HTTPS: SAFE")
    else:
        score += 15
        checks.append({'feature': 'HTTPS Status', 'result': scheme, 'risk': 'SUSPICIOUS', 'icon': '⚠', 'description': 'Unusual protocol.'})
        logs.append(f"[WARNING] Unusual scheme: {scheme} (+15)")

    # ══════════════════════════════════════════════════════════════════════════
    # RULE 3: Subdomain Depth (Phishers love deep subdomains)
    # ══════════════════════════════════════════════════════════════════════════
    logs.append("Analyzing subdomain depth...")
    subdomain_count = len(subdomain.split('.')) if subdomain else 0

    if subdomain_count >= 3:
        score += 30
        checks.append({'feature': 'Subdomain Count', 'result': f'{subdomain_count} levels', 'risk': 'DANGEROUS', 'icon': '✖', 'description': 'Excessive subdomains — common impersonation tactic.'})
        logs.append(f"[ALERT] Excessive subdomains (+30 points)")
    elif subdomain_count == 2:
        score += 15
        checks.append({'feature': 'Subdomain Count', 'result': f'{subdomain_count} levels', 'risk': 'SUSPICIOUS', 'icon': '⚠', 'description': 'Multiple subdomains found.'})
        logs.append(f"[WARNING] Multiple subdomains (+15 points)")
    else:
        checks.append({'feature': 'Subdomain Count', 'result': f'{subdomain_count} level(s)', 'risk': 'SAFE', 'icon': '✔', 'description': 'Normal depth.'})
        logs.append("Subdomain check: SAFE")

    # ══════════════════════════════════════════════════════════════════════════
    # RULE 4: Suspicious Keywords
    # ══════════════════════════════════════════════════════════════════════════
    logs.append("Scanning for suspicious keywords...")
    url_lower = url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

    if len(found_keywords) >= 3:
        score += 30
        checks.append({'feature': 'Suspicious Keywords', 'result': ', '.join(found_keywords), 'risk': 'DANGEROUS', 'icon': '✖', 'description': 'Multiple phishing keywords detected.'})
        logs.append(f"[ALERT] Multiple keywords (+30 points)")
    elif len(found_keywords) >= 1:
        score += 20
        checks.append({'feature': 'Suspicious Keywords', 'result': ', '.join(found_keywords), 'risk': 'SUSPICIOUS', 'icon': '⚠', 'description': 'Phishing-related keywords found.'})
        logs.append(f"[WARNING] Keywords found (+20 points)")
    else:
        checks.append({'feature': 'Suspicious Keywords', 'result': 'None', 'risk': 'SAFE', 'icon': '✔', 'description': 'No suspicious keywords.'})
        logs.append("Keyword scan: SAFE")

    # ══════════════════════════════════════════════════════════════════════════
    # RULE 5: URL Length
    # ══════════════════════════════════════════════════════════════════════════
    logs.append("Checking URL length...")
    url_length = len(url)
    if url_length > 120:
        score += 20
        checks.append({'feature': 'URL Length', 'result': f'{url_length} chars', 'risk': 'SUSPICIOUS', 'icon': '⚠', 'description': 'Very long URL — often hides destination.'})
        logs.append(f"[WARNING] Very long URL (+20 points)")
    elif url_length > 80:
        score += 10
        checks.append({'feature': 'URL Length', 'result': f'{url_length} chars', 'risk': 'SUSPICIOUS', 'icon': '⚠', 'description': 'Moderately long URL.'})
        logs.append(f"[WARNING] Long URL (+10 points)")
    else:
        checks.append({'feature': 'URL Length', 'result': f'{url_length} chars', 'risk': 'SAFE', 'icon': '✔', 'description': 'Normal length.'})
        logs.append("URL length: SAFE")

    # ══════════════════════════════════════════════════════════════════════════
    # RULE 6: URL Shorteners
    # ══════════════════════════════════════════════════════════════════════════
    logs.append("Checking for URL shorteners...")
    is_shortener = any(s in hostname for s in URL_SHORTENERS)
    if is_shortener:
        score += 25
        checks.append({'feature': 'URL Shortener', 'result': hostname, 'risk': 'SUSPICIOUS', 'icon': '⚠', 'description': 'Shortened URL — hides real destination. Verify carefully.'})
        logs.append(f"[WARNING] URL shortener detected (+25 points)")
    else:
        checks.append({'feature': 'URL Shortener', 'result': 'None', 'risk': 'SAFE', 'icon': '✔', 'description': 'Not a known shortener.'})
        logs.append("Shortener check: SAFE")

    # ══════════════════════════════════════════════════════════════════════════
    # RULE 7: Suspicious TLDs
    # ══════════════════════════════════════════════════════════════════════════
    logs.append("Checking TLD...")
    if any(tld in domain.lower() for tld in SUSPICIOUS_TLDS):
        score += 20
        checks.append({'feature': 'Suspicious TLD', 'result': tld, 'risk': 'SUSPICIOUS', 'icon': '⚠', 'description': 'Uncommon TLD often used in phishing.'})
        logs.append(f"[WARNING] Suspicious TLD detected (+20 points)")
    else:
        checks.append({'feature': 'TLD Check', 'result': tld or 'None', 'risk': 'SAFE', 'icon': '✔', 'description': 'Common TLD.'})
        logs.append("TLD check: SAFE")

# ══════════════════════════════════════════════════════════════════════════
    # RULE 8: UPI Payment Link (Neutral detection - no risk penalty for legit UPI)
    # ══════════════════════════════════════════════════════════════════════════
    logs.append("Checking for UPI parameters...")
    query_params = parse_qs(query_str)
    found_upi = [p for p in UPI_PARAMS if p in query_params]
    is_upi_link = url.startswith('upi://') or bool(found_upi)

    if is_upi_link:
        # NO risk score added - legit UPI is SAFE unless other red flags
        result['upi_detected'] = True
        
        # Parse UPI details (decode URL params)
        query_params = parse_qs(query_str, keep_blank_values=True)
        upi_details = {
            'vpa': query_params.get('pa', ['N/A'])[0] if query_params.get('pa') else 'N/A',
            'payee_name': query_params.get('pn', ['N/A'])[0] if query_params.get('pn') else 'N/A',
            'amount': query_params.get('am', ['N/A'])[0] if query_params.get('am') else 'N/A',
            'currency': query_params.get('cu', ['INR'])[0] if query_params.get('cu') else 'INR',
            'note': query_params.get('tn', ['N/A'])[0] if query_params.get('tn') else 'N/A',
        }
        result['upi_details'] = upi_details
        
        result_str = f"VPA: {upi_details['vpa'][:20]}{'...' if len(upi_details['vpa']) > 20 else ''}"
        checks.append({'feature': 'UPI Payment Link', 'result': result_str, 'risk': 'INFO', 'icon': 'ℹ', 'description': 'Legitimate UPI payment request. Verify payee details before authorizing.'})
        logs.append(f"[INFO] Legit UPI link detected (no risk added): {result_str}")
    else:
        checks.append({'feature': 'UPI Parameters', 'result': 'None', 'risk': 'SAFE', 'icon': '✔', 'description': 'No UPI payment parameters found.'})
        logs.append("UPI check: SAFE")

    # ══════════════════════════════════════════════════════════════════════════
    # RULE 9: Domain Structure (Hyphens + basic typo-squatting)
    # ══════════════════════════════════════════════════════════════════════════
    logs.append("Checking domain structure...")
    hyphen_count = domain.count('-')
    # Basic typo check (numbers instead of letters, repeated chars, etc.)
    typo_pattern = bool(re.search(r'[0-9]{2,}|(.)\1{2,}', domain))  # e.g., paypa11, go00gle

    if hyphen_count >= 2 or typo_pattern:
        score += 20
        checks.append({'feature': 'Domain Structure', 'result': domain, 'risk': 'SUSPICIOUS', 'icon': '⚠', 'description': 'Suspicious domain pattern (hyphens or typo-like).'})
        logs.append(f"[WARNING] Suspicious domain structure (+20 points)")
    elif hyphen_count == 1:
        score += 8
        checks.append({'feature': 'Domain Structure', 'result': domain, 'risk': 'SUSPICIOUS', 'icon': '⚠', 'description': 'Single hyphen — verify carefully.'})
        logs.append(f"[WARNING] Hyphen in domain (+8 points)")
    else:
        checks.append({'feature': 'Domain Structure', 'result': domain, 'risk': 'SAFE', 'icon': '✔', 'description': 'Clean domain structure.'})
        logs.append("Domain structure: SAFE")

    # ── Final scoring & classification ───────────────────────────────────────
    score = min(score, 100)
    result['risk_score'] = score

    logs.append("Calculating final risk score...")

    if score <= 20:
        result['risk_level'] = 'SAFE'
        logs.append(f"Final Score: {score}/100 → SAFE ✔")
    elif score <= 50:
        result['risk_level'] = 'SUSPICIOUS'
        logs.append(f"Final Score: {score}/100 → SUSPICIOUS ⚠")
    else:
        result['risk_level'] = 'HIGH RISK'
        logs.append(f"Final Score: {score}/100 → HIGH RISK ✖")

    logs.append("Analysis complete.")

    return result


# (decode_qr_code and get_security_recommendations functions remain unchanged)
# Paste your original decode_qr_code and get_security_recommendations here
# (they are fine as-is)

def decode_qr_code(image_path: str) -> str | None:
    try:
        import cv2
        from pyzbar import pyzbar
        image = cv2.imread(image_path)
        if image is None:
            return None
        decoded_objects = pyzbar.decode(image)
        if decoded_objects:
            return decoded_objects[0].data.decode('utf-8')
        return None
    except Exception:
        return None


def get_security_recommendations(risk_level: str, checks: list) -> list:
    recommendations = []

    if risk_level == 'HIGH RISK':
        recommendations.extend([
            "⛔ DO NOT visit this link or enter any information.",
            "⛔ Report this as phishing.",
            "🛡 Scan your device if you clicked it.",
            "🔒 Change passwords if you entered any data.",
        ])
    elif risk_level == 'SUSPICIOUS':
        recommendations.extend([
            "⚠ Proceed with extreme caution.",
            "⚠ Manually type the official domain instead of clicking the link.",
            "🔍 Verify the exact domain name.",
            "📞 Contact the company directly via official channels.",
        ])
    else:
        recommendations.extend([
            "✔ This URL appears safe based on analysis.",
            "✔ Still verify the domain before entering sensitive data.",
            "🔒 Keep software and antivirus updated.",
        ])

    # Add context-specific ones
    for check in checks:
        if 'UPI' in check['feature'] and check['risk'] != 'SAFE':
            recommendations.append("💳 Always verify UPI payee in the official app before paying.")
        if 'IP Address' in check['feature'] and check['risk'] == 'DANGEROUS':
            recommendations.append("🌐 Never trust raw IP addresses.")

    return recommendations