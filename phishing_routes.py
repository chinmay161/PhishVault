from flask import Blueprint, request, jsonify
from urllib.parse import urlparse
import requests
import ssl, os
import socket
import whois
from datetime import datetime, time
import dns.resolver
from dotenv import load_dotenv
from models import db, ScanResult
from flask_login import current_user
import traceback
from flask_socketio import emit
from extensions import socketio
import time

# Define the blueprint
phishing_bp = Blueprint('phishing', __name__)

# Mock database for community reports
#community_reports_db = []

# Helper function: Validate and normalize URL
def validate_and_normalize_url(raw_url):
    if not raw_url:
        return None, "URL is required"

    # Add scheme if missing
    if not raw_url.startswith(('http://', 'https://')):
        raw_url = 'http://' + raw_url

    parsed_url = urlparse(raw_url)
    if not parsed_url.netloc:
        return None, "Invalid URL format"

    # Check if website exists (HEAD is faster)
    try:
        response = requests.head(raw_url, timeout=5, allow_redirects=True)
        if response.status_code >= 400:
            return None, "Website does not appear to exist or is unreachable"
    except Exception as e:
        return None, f"Website not reachable: {str(e)}"

    return parsed_url.geturl(), None

# Step 1: SSL Certificate Validation
def check_ssl_certificate(parsed_url):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=parsed_url.netloc) as s:
            s.connect((parsed_url.netloc, 443))
            cert = s.getpeercert()
        return {'valid': True, 'details': 'SSL certificate is valid.'}
    except Exception as e:
        return {'valid': False, 'details': 'No valid SSL certificate found.'}

# Step 2: Domain Age Analysis
def check_domain_age(parsed_url):
    try:
        domain_info = whois.whois(parsed_url.netloc)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        domain_age = (datetime.now() - creation_date).days
        status = 'New' if domain_age < 30 else 'Established'
        return {'age_days': domain_age, 'status': status, 'details': ''}
    except Exception as e:
        return {'age_days': 0, 'status': 'Unknown', 'details': str(e)}

# Step 3: Keyword Analysis
def check_suspicious_keywords(url):
    suspicious_keywords = ['urgent-action', 'verify-account', 'login', 'password']
    detected_keywords = [kw for kw in suspicious_keywords if kw in url.lower()]
    return {
        'detected': bool(detected_keywords),
        'keywords_found': detected_keywords if detected_keywords else ['No suspicious keywords found']
    }

# Step 4: Redirect Chain Analysis
def check_redirect_chain(url):
    try:
        response = requests.get(url, allow_redirects=True)
        redirect_count = len(response.history)
        if redirect_count > 3:  # More than 3 redirects is suspicious
            return {'clean': False, 'details': f"{redirect_count} redirects detected"}
        return {'clean': True, 'details': 'No suspicious redirects found.'}
    except Exception as e:
        return {'clean': False, 'details': f"Error checking redirects: {str(e)}"}

# Step 5: Threat Database Checks (Google Safe Browsing & PhishTank)
import json

def check_threat_databases(url):
    results = []

    # Google Safe Browsing
    try:
        google_safe_browsing_api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        google_safe_browsing_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
        payload = {
            "client": {"clientId": "PhishVault", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(
            f"{google_safe_browsing_url}?key={google_safe_browsing_api_key}",
            json=payload
        )
        gsb_result = response.json()
        results.append({
            'name': 'Google Safe Browsing',
            'status': 'Reported' if gsb_result.get('matches') else 'Safe'
        })
    except Exception as e:
        results.append({'name': 'Google Safe Browsing', 'status': 'Error', 'details': str(e)})

    # PhishTank from manually downloaded JSON
    try:
        with open('phishtank_data.json', 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Check if the URL is in the list
        is_phish = any(entry['url'].strip('/') == url.strip('/') for entry in data)
        results.append({
            'name': 'PhishTank',
            'status': 'Reported' if is_phish else 'Safe'
        })
    except Exception as e:
        results.append({'name': 'PhishTank', 'status': 'Error', 'details': str(e)})

    return results



# Step 6: IP Reputation Analysis (AbuseIPDB)
def check_ip_reputation(parsed_url):
    try:
        # Resolve the domain name to an IP address
        ip_address = socket.gethostbyname(parsed_url.netloc)

        # AbuseIPDB API key and endpoint
        abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
        abuseipdb_url = f'https://api.abuseipdb.com/api/v2/check'
        
        # Headers and parameters for the API request
        headers = {'Key': abuseipdb_api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        
        # Make the API request to AbuseIPDB
        response = requests.get(abuseipdb_url, headers=headers, params=params)

        result = response.json()

        # Extract relevant details from AbuseIPDB response
        data = result['data']

        # Fetch ASN and city using ip-api.com.
        # This API call fetches only the 'as' (ASN) and 'city' fields.
        ip_api_url = f"http://ip-api.com/json/{ip_address}?fields=as,city"
        ip_api_response = requests.get(ip_api_url)
        ip_api_data = ip_api_response.json()
        asn = ip_api_data.get("as", "Unknown")
        city = ip_api_data.get("city", "Unknown")

        return {
            'ip_address': ip_address,
            'isp': data.get('isp', 'Unknown'),
            'usage_type': data.get('usageType', 'Unknown'),
            'asn': asn,
            'domain_name': data.get('domain', 'Unknown'),
            'country': data.get('countryCode', 'Unknown'),
            'city': city,
            'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
            'details': data.get('reports', [])
        }
    except Exception as e:
        return {
            'ip_address': 'Unknown',
            'isp': 'Unknown',
            'usage_type': 'Unknown',
            'asn': 'Unknown',
            'domain_name': 'Unknown',
            'country': 'Unknown',
            'city': 'Unknown',
            'abuse_confidence_score': None,
            'details': f"Error checking IP reputation: {str(e)}"
        }
        

# Step 7: Technical Analysis (DNS Records)
def check_technical_details(parsed_url):
    try:
        dns_records = dns.resolver.resolve(parsed_url.netloc, 'A')
        return {
            'server_location': 'Unknown',
            'dns_records': [record.to_text() for record in dns_records],
            'details': ''
        }
    except Exception as e:
        return {'server_location': 'Unknown', 'dns_records': [], 'details': f"Error resolving DNS: {str(e)}"}

# Route for scanning URLs
@phishing_bp.route('/scan-url', methods=['POST'])
def scan_url():
    try:
        data = request.json
        raw_url = data.get('url')
        sid = request.args.get('sid')  # SocketIO session ID from frontend

        def notify(step, detail=""):
            socketio.emit('scan_progress', {'step': step, 'detail': detail}, room=sid)
            time.sleep(0.1)  # Small delay to allow UI updates

        # Validate URL
        notify("Validating URL")
        normalized_url, error = validate_and_normalize_url(raw_url)
        if error:
            notify("Validation Failed", error)
            return jsonify({'error': error}), 400

        parsed_url = urlparse(normalized_url)
        results = {'risk_score': 0}

        # Step-by-step scan with WebSocket updates
        notify("Checking SSL Certificate")
        results['ssl_certificate'] = check_ssl_certificate(parsed_url)
        
        notify("Checking Domain Age")
        results['domain_age'] = check_domain_age(parsed_url)
        
        notify("Checking for Suspicious Keywords")
        results['keywords'] = check_suspicious_keywords(normalized_url)
        
        notify("Checking Redirects")
        results['redirect_chain'] = check_redirect_chain(normalized_url)
        
        notify("Checking Threat Databases")
        results['threat_databases'] = check_threat_databases(normalized_url)
        
        notify("Checking IP Reputation")
        results['ip_reputation'] = check_ip_reputation(parsed_url)
        
        notify("Checking DNS Records")
        results['technical_details'] = check_technical_details(parsed_url)
        
        # Calculate risk score
        notify("Calculating Risk Score")
        score = 0
        if not results['ssl_certificate']['valid']:
            score += 15
        if results['domain_age']['status'] == 'New':
            score += 15
        if results['keywords']['detected']:
            score += 20
        if not results['redirect_chain']['clean']:
            score += 10
        if any(db['status'] == 'Reported' for db in results['threat_databases']):
            score += 20
        abuse_score = results['ip_reputation']['abuse_confidence_score']
        if abuse_score is not None and abuse_score >= 50:
            score += 20
        elif abuse_score is None:
            score += 5  # Penalize uncertainty
        
        results['risk_score'] = min(score, 100)
        results['status'] = "Safe" if results['risk_score'] < 40 else "malicious"

        # Save to DB if user is logged in
        if current_user.is_authenticated:
            scan = ScanResult(
                user_id=current_user.id,
                url=normalized_url,
                risk_score=results['risk_score'],
                status=results['status'],
                result_json=json.dumps(results)
            )
            db.session.add(scan)
            db.session.commit()

        notify("Scan Complete")
        return jsonify({**results, "refresh_dashboard": True}), 200

    except Exception as e:
        traceback.print_exc()
        socketio.emit('scan_progress', {'step': 'Error', 'detail': str(e)}, room=request.args.get('sid'))
        return jsonify({'error': 'An unexpected error occurred'}), 500