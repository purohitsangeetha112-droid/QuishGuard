# url_features.py
import re
from urllib.parse import urlparse

def extract_features(url):
    features = {}
    try:
        parsed = urlparse(url)
    except:
        parsed = urlparse("http://invalid.com")

    features['url_length'] = len(url)
    features['hostname_length'] = len(parsed.netloc) if parsed.netloc else 0
    features['has_https'] = 1 if parsed.scheme == 'https' else 0

    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features['has_ip'] = 1 if re.match(ip_pattern, parsed.netloc or '') else 0
    features['dot_count'] = (parsed.netloc or '').count('.')
    features['hyphen_count'] = (parsed.netloc or '').count('-')

    parts = (parsed.netloc or '').split('.')
    features['subdomain_count'] = max(0, len(parts) - 2)

    suspicious_words = ['login', 'verify', 'secure', 'account', 'update',
                       'confirm', 'password', 'banking', 'signin', 'free',
                       'gift', 'prize', 'winner', 'claim']
    url_lower = url.lower()
    features['suspicious_word_count'] = sum(1 for w in suspicious_words if w in url_lower)
    features['hostname_has_suspicious_word'] = 1 if any(
        w in (parsed.netloc or '').lower() for w in suspicious_words
    ) else 0

    features['path_length'] = len(parsed.path) if parsed.path else 0
    features['query_param_count'] = len(parsed.query.split('&')) if parsed.query else 0
    features['has_at_symbol'] = 1 if '@' in url else 0

    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']
    features['suspicious_tld'] = 1 if any(
        (parsed.netloc or '').lower().endswith(t) for t in suspicious_tlds
    ) else 0

    return features