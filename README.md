# 🛡️ QuishGuard

Real-time QR Phishing (Quishing) Detector for UPI/Payments

## Problem
Quishing = phishing via QR codes. Attackers put malicious URLs in QR codes on posters, emails, fake payment stands, etc. In India, this directly affects UPI, digital wallets, and small merchants.

## Solution
QuishGuard is an explainable QR phishing detector that:
- Decodes QR codes from uploaded images
- Analyzes URLs with a hybrid rule-based + ML approach
- Explains WHY a URL is suspicious (not just "safe/unsafe")
- Detects UPI payment links and validates VPAs

## Tech Stack
- **Backend:** Python, Flask, scikit-learn (Random Forest)
- **Frontend:** HTML, CSS, JavaScript, Chart.js
- **QR Decoding:** OpenCV
- **Explainability:** Feature importance + threshold-based rules

## How to Run

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/QuishGuard.git
cd QuishGuard
