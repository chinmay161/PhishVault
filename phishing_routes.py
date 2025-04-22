from flask import Blueprint, request, jsonify
from urllib.parse import urlparse
import requests
import ssl, os
import socket
import whois
from datetime import datetime
import dns.resolver
from dotenv import load_dotenv

# Define the blueprint
phishing_bp = Blueprint('phishing', __name__)

# Mock database for community reports
community_reports_db = []

# Helper function: Validate and normalize URL
def validate_and_normalize_url(raw_url):
    if not raw_url:
        return None, "URL is required"
    
    parsed_url = urlparse(raw_url)
    if not parsed_url.scheme:  # If no scheme (http/https) is provided
        raw_url = f"http://{raw_url}"  # Default to http://
    
    parsed_url = urlparse(raw_url)
    if not parsed_url.netloc:  # If the URL is still invalid
        return None, "Invalid URL format"
    
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
        return {'valid': False, 'details': str(e)}

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
    return {'detected': len(detected_keywords) > 0, 'keywords_found': detected_keywords}

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
        print(f"[DEBUG] Resolved IP for {parsed_url.netloc}: {ip_address}")  # Debug log

        # AbuseIPDB API key and endpoint
        abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
        abuseipdb_url = f'https://api.abuseipdb.com/api/v2/check'
        
        # Headers and parameters for the API request
        headers = {'Key': abuseipdb_api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        print(f"[DEBUG] Requesting AbuseIPDB with params: {params}")  # Debug log
        
        # Make the API request to AbuseIPDB
        response = requests.get(abuseipdb_url, headers=headers, params=params)
        print(f"[DEBUG] AbuseIPDB HTTP Status: {response.status_code}")  # Debug log

        result = response.json()
        print(f"[DEBUG] AbuseIPDB response: {result}")  # Debug log

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
            'abuse_confidence_score': 0,
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
        # Get the raw URL from the request
        data = request.json
        raw_url = data.get('url')

        # Validate and normalize the URL
        normalized_url, error = validate_and_normalize_url(raw_url)
        if error:
            return jsonify({'error': error}), 400

        # Parse the normalized URL
        parsed_url = urlparse(normalized_url)

        # Initialize results dictionary
        results = {
            'risk_score': 0,
            'ssl_certificate': check_ssl_certificate(parsed_url),
            'domain_age': check_domain_age(parsed_url),
            'keywords': check_suspicious_keywords(normalized_url),
            'redirect_chain': check_redirect_chain(normalized_url),
            'threat_databases': check_threat_databases(normalized_url),
            'ip_reputation': check_ip_reputation(parsed_url),
            'technical_details': check_technical_details(parsed_url),
            'community_reports': community_reports_db
        }

        # Calculate Risk Score
        risk_score = 0
        if not results['ssl_certificate']['valid']:
            risk_score += 20
        if results['domain_age']['age_days'] < 30:
            risk_score += 20
        if results['keywords']['detected']:
            risk_score += 20
        if not results['redirect_chain']['clean']:
            risk_score += 20
        if any(db['status'] == 'Reported' for db in results['threat_databases']):
            risk_score += 20
        if results['ip_reputation']['abuse_confidence_score'] > 50:
            risk_score += 20

        results['risk_score'] = min(risk_score, 100)

        return jsonify(results), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500