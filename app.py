# app.py
from flask import Flask, request, jsonify, render_template
from url_analyzer import URLAnalyzer
from urllib.parse import urlparse, parse_qs
import cv2
import numpy as np
import re

app = Flask(__name__)

print("Loading model...")
analyzer = URLAnalyzer()
print("QuishGuard API ready!")


# ---------- UPI helpers ----------
def extract_upi_info(url):
    """If URL is a UPI payment link, extract its fields."""
    if not url.lower().startswith('upi://'):
        return None
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {
            'vpa': params.get('pa', [''])[0],
            'payee_name': params.get('pn', [''])[0],
            'amount': params.get('am', [''])[0],
            'transaction_note': params.get('tn', [''])[0],
        }
    except Exception:
        return None


def is_vpa_suspicious(vpa):
    """Heuristic to flag suspicious VPAs."""
    if not vpa:
        return False, "No VPA found"
    reasons = []
    if '@' not in vpa:
        reasons.append("VPA has no '@' handle")
    local, _, handle = vpa.partition('@')
    if len(local) < 3:
        reasons.append("VPA local part is very short")
    if handle.lower() in ['xyz', 'fake', 'test', 'temp']:
        reasons.append(f"Suspicious VPA handle: @{handle}")
    if re.search(r'\d{6,}', local):
        reasons.append("VPA contains long digit sequence")
    return len(reasons) > 0, "; ".join(reasons) if reasons else "Looks OK"


# ---------- Routes ----------
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})


@app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Please provide a URL'}), 400

    url = data['url']

    # UPI-specific handling
    upi_info = extract_upi_info(url)
    upi_warning = None
    if upi_info:
        suspicious, reason = is_vpa_suspicious(upi_info['vpa'])
        upi_warning = {'is_suspicious': suspicious, 'reason': reason}

    # Standard analysis
    result = analyzer.analyze(url)

    response = {
        'url': url,
        'verdict': result['verdict'],
        'phishing_probability': round(result['phishing_probability'], 4),
        'confidence': round(result['confidence'], 4),
        'explanations': [
            {
                'feature': e['feature'],
                'description': e['description'],
                'impact': e['impact']
            }
            for e in result['explanations']
        ],
        'detection_method': result.get('detection_method', 'ml'),
    }
    if upi_info:
        response['upi_info'] = upi_info
        response['upi_warning'] = upi_warning
    return jsonify(response)


@app.route('/batch_analyze', methods=['POST'])
def batch_analyze():
    """Analyze multiple URLs at once."""
    data = request.get_json()
    urls = data.get('urls', [])
    if not urls:
        return jsonify({'error': 'No URLs provided'}), 400
    if len(urls) > 50:
        return jsonify({'error': 'Maximum 50 URLs per batch'}), 400

    results = []
    for url in urls:
        url = url.strip()
        if not url:
            continue
        try:
            r = analyzer.analyze(url)
            results.append({
                'url': url,
                'verdict': r['verdict'],
                'phishing_probability': round(r['phishing_probability'], 4),
            })
        except Exception as e:
            results.append({'url': url, 'verdict': 'ERROR', 'error': str(e)})
    return jsonify({'results': results})


@app.route('/upload_qr', methods=['POST'])
def upload_qr():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        image_bytes = file.read()
        image_np = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(image_np, cv2.IMREAD_COLOR)
        if img is None:
            return jsonify({'error': 'Could not read image file'}), 400

        url = None
        detector = cv2.QRCodeDetector()

        url, _, _ = detector.detectAndDecode(img)
        if not url:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            url, _, _ = detector.detectAndDecode(gray)
        if not url:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            h, w = gray.shape
            url, _, _ = detector.detectAndDecode(cv2.resize(gray, (w*2, h*2), interpolation=cv2.INTER_CUBIC))
        if not url:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            url, _, _ = detector.detectAndDecode(thresh)
        if not url:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            blurred = cv2.medianBlur(gray, 3)
            _, thresh = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            h, w = thresh.shape
            url, _, _ = detector.detectAndDecode(cv2.resize(thresh, (w*2, h*2), interpolation=cv2.INTER_CUBIC))

        if not url:
            return jsonify({'error': 'No QR code found. Try a clearer black-and-white QR.'}), 400

        upi_info = extract_upi_info(url)
        result = analyzer.analyze(url)

        response = {
            'url': url,
            'verdict': result['verdict'],
            'phishing_probability': round(result['phishing_probability'], 4),
            'confidence': round(result['confidence'], 4),
            'explanations': [
                {'feature': e['feature'], 'description': e['description'], 'impact': e['impact']}
                for e in result['explanations']
            ],
            'detection_method': result.get('detection_method', 'ml'),
        }
        if upi_info:
            response['upi_info'] = upi_info
            response['upi_warning'] = {'is_suspicious': is_vpa_suspicious(upi_info['vpa'])[0],
                                       'reason': is_vpa_suspicious(upi_info['vpa'])[1]}
        return jsonify(response)

    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)