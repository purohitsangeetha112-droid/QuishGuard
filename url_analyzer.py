# url_analyzer.py
import joblib
import pandas as pd
from urllib.parse import urlparse
from url_features import extract_features

# ============================================================
# TRUSTED DOMAINS — these are always SAFE, no ML needed
# ============================================================
TRUSTED_DOMAINS = {
    # Global tech
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'x.com', 'linkedin.com', 'github.com',
    'microsoft.com', 'apple.com', 'amazon.com', 'amazon.in',
    'wikipedia.org', 'reddit.com', 'netflix.com', 'whatsapp.com',
    'stackoverflow.com', 'medium.com', 'quora.com',
    # Indian banks
    'sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com',
    'hdfcbank.com', 'icicibank.com', 'axisbank.com',
    'kotak.com', 'kotakbank.com', 'yesbank.in',
    'pnbindia.in', 'bankofbaroda.in', 'canarabank.com',
    'unionbankofindia.co.in', 'idfcfirstbank.com',
    'indusind.com', 'federalbank.co.in',
    # Indian payment / UPI
    'paytm.com', 'phonepe.com', 'bhimupi.org.in',
    'npci.org.in', 'upi.com', 'googlepay.com',
    'pay.google.com', 'amazonpay.in', 'mobikwik.com',
    'freecharge.in', 'cred.club',
    # Indian e-commerce / services
    'flipkart.com', 'myntra.com', 'snapdeal.com',
    'swiggy.com', 'zomato.com', 'ola.cab', 'uber.com',
    'irctc.co.in', 'airtel.in', 'jio.com', 'vodafone.in',
    'bsnl.co.in', 'india.gov.in', 'gov.in', 'nic.in',
    # Education
    'iitb.ac.in', 'iitd.ac.in', 'iitm.ac.in',
    'du.ac.in', 'ugc.ac.in', 'aicte-india.org',
}

# ============================================================
# KNOWN PHISHING PATTERNS — always DANGEROUS
# ============================================================
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link'}
PHISHING_KEYWORDS = ['login', 'verify', 'secure', 'account', 'update',
                     'confirm', 'password', 'banking', 'signin', 'kyc',
                     'netbanking', 'net-banking', 'cashback', 'reward',
                     'winner', 'prize', 'claim', 'free-gift', 'offer']


class URLAnalyzer:
    def __init__(self, model_path='phishing_model.pkl'):
        self.model = joblib.load(model_path)
        self.global_importance = dict(zip(
            self.model.feature_names_in_,
            self.model.feature_importances_
        ))
        print("URL Analyzer ready.")

    def _extract_domain(self, url):
        """Get the root domain (e.g., 'google.com' from 'https://mail.google.com/x')."""
        try:
            parsed = urlparse(url if '://' in url else 'http://' + url)
            host = parsed.netloc.lower()
            # Remove www. and port
            host = host.split(':')[0]
            if host.startswith('www.'):
                host = host[4:]
            return host
        except:
            return ''

    def _is_trusted(self, url):
        """Check if URL belongs to a trusted domain (or subdomain of one)."""
        domain = self._extract_domain(url)
        # Exact match
        if domain in TRUSTED_DOMAINS:
            return True
        # Subdomain of trusted domain (e.g., mail.google.com → google.com)
        for trusted in TRUSTED_DOMAINS:
            if domain.endswith('.' + trusted):
                return True
        return False

    def _hard_rules_check(self, url):
        """
        Rule-based detection for obvious phishing signals.
        Returns (verdict, reason) or (None, None) if no rule triggers.
        """
        domain = self._extract_domain(url)
        url_lower = url.lower()

        # Rule 1: Raw IP address (no domain name)
        if domain.replace('.', '').isdigit():
            return 'DANGEROUS', 'Uses a raw IP address instead of a domain name'

        # Rule 2: Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return 'DANGEROUS', f'Uses a suspicious top-level domain ({tld})'

        # Rule 3: Trusted brand name + suspicious extra words in domain
        brand_words = ['paytm', 'phonepe', 'sbi', 'hdfc', 'icici', 'axis',
                       'google', 'amazon', 'flipkart', 'paypal', 'upi', 'bhim',
                       'gpay', 'googlepay']
        for brand in brand_words:
            if brand in domain and domain not in TRUSTED_DOMAINS:
                # Brand name is in the domain but the domain isn't the real one
                for trusted in TRUSTED_DOMAINS:
                    if brand in trusted and not domain.endswith(trusted):
                        return 'DANGEROUS', f'Impersonates "{brand}" — real domain is {trusted}'

        # Rule 4: @ symbol trick (e.g., google.com@evil.com)
        if '@' in url:
            return 'DANGEROUS', 'Contains @ symbol (can hide the real domain)'

        # Rule 5: Excessive hyphens in domain
        if domain.count('-') >= 2:
            return 'DANGEROUS', 'Domain has multiple hyphens (common in fake domains)'

        # Rule 6: HTTP (not HTTPS) + suspicious keyword
        if url_lower.startswith('http://'):
            keyword_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)
            if keyword_hits >= 1:
                return 'DANGEROUS', 'Insecure HTTP with suspicious keyword in URL'

        # No hard rule triggered
        return None, None

    def analyze(self, url):
        """Analyze a URL with rule-based + ML hybrid."""
        features = extract_features(url)

        # ---------- LAYER 1: Trusted domain whitelist ----------
        if self._is_trusted(url):
            return {
                'verdict': 'SAFE',
                'confidence': 0.99,
                'phishing_probability': 0.01,
                'features': features,
                'explanations': [{
                    'feature': 'trusted_domain',
                    'value': 1,
                    'impact': -0.99,
                    'description': '✅ Domain is on the verified trusted list'
                }],
                'detection_method': 'whitelist'
            }

        # ---------- LAYER 2: Hard rules ----------
        rule_verdict, rule_reason = self._hard_rules_check(url)
        if rule_verdict == 'DANGEROUS':
            return {
                'verdict': 'DANGEROUS',
                'confidence': 0.95,
                'phishing_probability': 0.95,
                'features': features,
                'explanations': [{
                    'feature': 'rule_match',
                    'value': 1,
                    'impact': 0.95,
                    'description': f'⚠️ {rule_reason}'
                }],
                'detection_method': 'rules'
            }

        # ---------- LAYER 3: Machine Learning ----------
        features_df = pd.DataFrame([features])
        probabilities = self.model.predict_proba(features_df)[0]
        phishing_probability = float(probabilities[1])

        if phishing_probability >= 0.7:
            verdict = 'DANGEROUS'
        elif phishing_probability >= 0.4:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'SAFE'

        explanations = self._explain(features, phishing_probability)

        return {
            'verdict': verdict,
            'confidence': float(max(probabilities)),
            'phishing_probability': phishing_probability,
            'features': features,
            'explanations': explanations,
            'detection_method': 'ml'
        }

    def _explain(self, features, phishing_probability):
        """Build explanations using thresholds + global importance."""
        thresholds = {
            'url_length': 75, 'hostname_length': 30, 'dot_count': 3,
            'hyphen_count': 1, 'subdomain_count': 2, 'suspicious_word_count': 1,
            'path_length': 50, 'query_param_count': 3,
            'has_https': 0, 'has_ip': 1, 'hostname_has_suspicious_word': 1,
            'has_at_symbol': 1, 'suspicious_tld': 1,
        }
        descriptions = {
            'url_length': "URL is very long",
            'hostname_length': "Domain name is very long",
            'has_https': "Does NOT use HTTPS (insecure connection)",
            'has_ip': "Domain is a raw IP address (very suspicious)",
            'dot_count': "Domain has too many dots",
            'hyphen_count': "Domain has many hyphens (fake brand pattern)",
            'subdomain_count': "Too many nested subdomains",
            'suspicious_word_count': "Contains suspicious words like 'login', 'verify'",
            'hostname_has_suspicious_word': "Domain itself contains a suspicious word",
            'path_length': "URL path is unusually long",
            'query_param_count': "Excessive URL parameters",
            'has_at_symbol': "Contains '@' symbol (can hide real domain)",
            'suspicious_tld': "Uses a suspicious TLD (.tk, .xyz, .top, etc.)",
        }
        binary = {'has_https', 'has_ip', 'hostname_has_suspicious_word',
                  'has_at_symbol', 'suspicious_tld'}

        explanations = []
        for feature_name, value in features.items():
            if feature_name not in thresholds:
                continue
            threshold = thresholds[feature_name]
            if feature_name in binary:
                is_suspicious = (value == threshold)
            else:
                is_suspicious = (value >= threshold)

            if not is_suspicious:
                continue

            global_weight = self.global_importance.get(feature_name, 0.05)
            explanations.append({
                'feature': feature_name,
                'value': int(value),
                'impact': round(float(global_weight), 4),
                'description': descriptions.get(feature_name, feature_name)
            })

        explanations.sort(key=lambda x: abs(x['impact']), reverse=True)
        return explanations[:5]