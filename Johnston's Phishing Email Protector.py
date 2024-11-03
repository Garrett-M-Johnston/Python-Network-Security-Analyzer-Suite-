import email
import re
from collections import defaultdict
import urllib.parse

def check_email_headers(headers):
    indicators = defaultdict(list)
    suspicious_count = 0
    
    for header, value in headers:
        header = header.lower()
        if header in ['from', 'reply-to']:
            indicators[header].append(value)
            if '@example.com' in value:  # Add your suspicious domains
                suspicious_count += 1
        elif header == 'received':
            indicators['received'].append(value)
    
    indicators['suspicious_header_score'] = suspicious_count
    return indicators

def check_email_body(body):
    indicators = []
    suspicious_count = 0
    
    # Check for suspicious URLs
    urls = re.findall(r'https?://\S+', body)
    for url in urls:
        if any(domain in url.lower() for domain in ['bit.ly', 'tinyurl.com']):
            indicators.append(f'Suspicious URL: {url}')
            suspicious_count += 1
    
    # Check for urgent language
    urgent_words = ['urgent', 'immediate', 'action required', 'account suspended']
    for word in urgent_words:
        if word.lower() in body.lower():
            indicators.append(f'Urgent language: {word}')
            suspicious_count += 1
    
    return indicators, suspicious_count

def check_attachments(email_msg):
    indicators = []
    suspicious_count = 0
    
    for part in email_msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        filename = part.get_filename()
        if filename:
            if any(ext in filename.lower() for ext in ['.exe', '.zip', '.js', '.bat']):
                indicators.append(f'Suspicious attachment: {filename}')
                suspicious_count += 1
    
    return indicators, suspicious_count

def analyze_email(email_msg):
    results = {
        'risk_score': 0,
        'findings': defaultdict(list)
    }
    
    # Check headers
    header_results = check_email_headers(email_msg.items())
    results['findings']['headers'] = dict(header_results)
    results['risk_score'] += header_results.get('suspicious_header_score', 0)
    
    # Check body
    body_indicators, body_score = check_email_body(email_msg.get_payload())
    results['findings']['body'] = body_indicators
    results['risk_score'] += body_score
    
    # Check attachments
    attachment_indicators, attachment_score = check_attachments(email_msg)
    results['findings']['attachments'] = attachment_indicators
    results['risk_score'] += attachment_score
    
    # Calculate risk level
    if results['risk_score'] >= 5:
        results['risk_level'] = 'HIGH'
    elif results['risk_score'] >= 3:
        results['risk_level'] = 'MEDIUM'
    else:
        results['risk_level'] = 'LOW'
    
    return results

def main():
    # Test the detector
    try:
        with open('phishing_email.eml', 'r') as f:
            email_msg = email.message_from_string(f.read())
        
        results = analyze_email(email_msg)
        
        print("\n=== Phishing Email Analysis Results ===")
        print(f"\nRisk Level: {results['risk_level']}")
        print(f"Risk Score: {results['risk_score']}")
        
        print("\nFindings:")
        for category, findings in results['findings'].items():
            print(f"\n{category.upper()}:")
            if isinstance(findings, dict):
                for key, value in findings.items():
                    print(f"- {key}: {value}")
            else:
                for finding in findings:
                    print(f"- {finding}")
                    
    except FileNotFoundError:
        print("Error: phishing_email.eml not found. Please create a test email first.")

if __name__ == '__main__':
    main()