<div align="center">

# 🛡️ QuishGuard

### Real-Time QR Phishing (Quishing) Detector for UPI & Digital Payments

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![OpenCV](https://img.shields.io/badge/OpenCV-4.x-5C3EE8?style=for-the-badge&logo=opencv&logoColor=white)](https://opencv.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

**An explainable, India-focused QR phishing detector that tells you not just *if* a QR is dangerous — but *why*.**

[Features](#-features) · [Screenshots](#-screenshots) · [How It Works](#-how-it-works) · [Setup](#-setup--installation) · [Tech Stack](#-tech-stack)

</div>

---

## 🚨 The Problem

**Quishing** = phishing via QR codes. Attackers hide malicious URLs inside QR codes placed on posters, WhatsApp messages, emails, and even physical payment stands.

In India, this directly threatens:
- 🏦 **UPI transactions** (PhonePe, Paytm, GPay, BHIM)
- 💳 **Digital wallet users**
- 🏪 **Small merchants** who scan QR codes dozens of times a day
- 👴 **First-time digital payment users** who can't inspect URLs

**Existing defenses are broken:**
- ❌ "Don't scan unknown QRs" — awareness alone doesn't scale
- ❌ Black-box ML models that say "safe/unsafe" with no explanation
- ❌ Users and security analysts can't explain *why* a QR was flagged

---

## ✨ Our Solution

QuishGuard is a **practical, explainable, mobile-friendly** quishing detector built for the Indian payment ecosystem.

### 🎯 Key Differentiators

| Feature | QuishGuard | Typical Detectors |
|---------|:---:|:---:|
| Explains *why* a QR is dangerous | ✅ | ❌ |
| UPI VPA detection & validation | ✅ | ❌ |
| Trusted-domain whitelist (Indian banks) | ✅ | ❌ |
| Hybrid rules + ML (no black box) | ✅ | ❌ |
| Batch URL analysis | ✅ | ❌ |
| Works entirely locally | ✅ | ❌ |

---

## 🖼️ Screenshots

### 🏠 Main Dashboard
<img width="1920" height="1020" alt="landing_page" src="https://github.com/user-attachments/assets/1d3e3841-d906-4e51-b75d-9e02e39712c0" />


*A modern, animated interface with dark/light theme, live particle background, and glassmorphism design.*

### ✅ Safe URL Detection
<img width="1920" height="1020" alt="safe_verdit" src="https://github.com/user-attachments/assets/87beaf64-de5b-4fe0-80a7-a6a73ea7f4c4" />


*Trusted Indian banking domains are recognized instantly with an animated risk gauge.*

### 🔴 Phishing Detection with Explanation
<img width="1920" height="1020" alt="dangerous_verdict" src="https://github.com/user-attachments/assets/289580d0-12c3-4756-b959-1d6fd1d3e78b" />


*Each verdict includes human-readable explanations and impact scores — no black-box decisions.*

### 📊 Statistics Dashboard
<img width="1261" height="561" alt="stats" src="https://github.com/user-attachments/assets/6c2412dd-c150-4d46-a11e-44ca56f99156" />


*Live charts of your scan history with scan breakdown by verdict type.*

---

## 🚀 Features

### 🔍 Core Detection
- **QR Image Decoding** — Upload or drag-and-drop QR code screenshots (OpenCV, 5 decode strategies)
- **Hybrid Analysis** — Whitelist + rules + ML for maximum accuracy
- **Explainable Verdicts** — Every decision comes with human-readable reasons
- **UPI Link Support** — Detects `upi://pay` links and extracts VPA, payee, amount

### 🎨 Modern UI
- **Animated particle background** with live network visualization
- **Dark / Light theme** toggle with persistent preference
- **Animated SVG risk gauge** for visual verdict feedback
- **Toast notifications** with smooth animations
- **Fully responsive** — works on desktop, tablet, and mobile

### ⚡ Productivity
- **Live URL analysis** — analyzes as you type (debounced)
- **Batch processing** — up to 50 URLs at once
- **Persistent history** — stored locally in your browser
- **CSV / JSON export** — download your scan logs
- **Keyboard shortcuts** — `Ctrl+K` to focus URL input

### 🔐 Security & Privacy
- **Everything runs locally** — no data sent to third parties
- **No telemetry, no tracking**
- **Open source** — audit the code yourself

---

## 🧠 How It Works

QuishGuard uses a **three-layer hybrid detection** approach:

```
┌─────────────────────────────────────────────────────────┐
│                   INPUT (QR or URL)                     │
└──────────────────────┬──────────────────────────────────┘
                       ▼
         ┌─────────────────────────────┐
         │  LAYER 1: Trusted Whitelist │
         │  (Indian banks, UPI, Google)│
         └─────────────┬───────────────┘
                       ▼
         ┌─────────────────────────────┐
         │  LAYER 2: Hard-Coded Rules  │
         │  • Raw IP address           │
         │  • Suspicious TLD (.tk, .xyz)│
         │  • Brand impersonation       │
         │  • @ symbol tricks           │
         │  • Excessive hyphens         │
         └─────────────┬───────────────┘
                       ▼
         ┌─────────────────────────────┐
         │  LAYER 3: ML Classifier     │
         │  (Random Forest, 13 features)│
         └─────────────┬───────────────┘
                       ▼
         ┌─────────────────────────────┐
         │  EXPLANATION LAYER          │
         │  Feature importance + rules │
         └─────────────────────────────┘
```

### Feature Extraction (13 features)

| # | Feature | Description |
|---|---------|-------------|
| 1 | `url_length` | Total URL length |
| 2 | `hostname_length` | Domain name length |
| 3 | `has_https` | HTTPS enabled? |
| 4 | `has_ip` | Domain is a raw IP address? |
| 5 | `dot_count` | Number of dots in domain |
| 6 | `hyphen_count` | Number of hyphens |
| 7 | `subdomain_count` | Number of subdomains |
| 8 | `suspicious_word_count` | Login/verify/secure/kyc, etc. |
| 9 | `hostname_has_suspicious_word` | Brand-word in domain |
| 10 | `path_length` | Length of URL path |
| 11 | `query_param_count` | Number of parameters |
| 12 | `has_at_symbol` | Contains `@` trick? |
| 13 | `suspicious_tld` | Uses .tk/.ml/.xyz/.top etc. |

---

## 🛠️ Setup & Installation

### Prerequisites
- **Python 3.11+** ([download](https://www.python.org/downloads/))
- **pip** (comes with Python)

### 1. Clone the repository

```bash
git clone https://github.com/purohitsangeetha112-droid/QuishGuard.git
cd QuishGuard
```

### 2. Create virtual environment

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**Mac / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Get the training dataset

Download the [Phishing URL Dataset (Kaggle)](https://www.kaggle.com/datasets/dattatejaofficial/phishing-url-dataset) and save it as `raw_data.csv` in the project root.

> **No Kaggle?** No problem — the included `phishing_urls.csv` has 30 sample URLs to get started. For production accuracy, use the full Kaggle dataset.

### 5. Train the model

```bash
python train_model_v2.py
```

You should see accuracy around **90–95%**.

### 6. Run the app

```bash
python app.py
```

### 7. Open in your browser

```
http://localhost:5000
```

---

## 💻 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.11, Flask |
| **Machine Learning** | scikit-learn (Random Forest) |
| **QR Decoding** | OpenCV (QRCodeDetector + preprocessing) |
| **Data Processing** | pandas, NumPy |
| **Frontend** | Vanilla JavaScript, HTML5, CSS3 |
| **Charts** | Chart.js 4 |
| **Design** | Custom glassmorphism + particle system |

---

## 📂 Project Structure

```
QuishGuard/
├── app.py                  # Flask API + routes
├── url_features.py         # 13-feature URL extractor
├── url_analyzer.py         # 3-layer hybrid detector
├── train_model.py          # Basic trainer (30 samples)
├── train_model_v2.py       # Full trainer (Kaggle dataset)
├── phishing_urls.csv       # Sample training data
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html          # Full UI (HTML/CSS/JS)
├── screenshots/            # README images
│   ├── 01-hero.png
│   ├── 02-safe-result.png
│   ├── 03-dangerous-result.png
│   └── 04-dashboard.png
└── README.md
```

---

## 🎯 Example Detections

| URL | Verdict | Why |
|-----|:---:|-----|
| `https://sbi.co.in` | 🟢 SAFE | Trusted whitelist |
| `https://google.com` | 🟢 SAFE | Trusted whitelist |
| `http://login-paytm-kyc.top/verify` | 🔴 DANGEROUS | Suspicious TLD + brand impersonation |
| `http://free-gift-iphone.tk/claim` | 🔴 DANGEROUS | Suspicious TLD + phishing keywords |
| `http://192.168.1.1/login` | 🔴 DANGEROUS | Raw IP address |
| `http://google.com@evil-site.xyz/login` | 🔴 DANGEROUS | @ symbol trick |
| `upi://pay?pa=fake@xyz&am=9999` | ⚠️ SUSPICIOUS | Suspicious VPA handle |

---

## 🧪 Testing

Run the app and try these URLs:

**Safe:**
- `https://google.com`
- `https://sbi.co.in`
- `https://phonepe.com`
- `https://flipkart.com`

**Dangerous:**
- `http://free-gift-iphone.tk/claim`
- `http://login-paytm-kyc.top/verify`
- `http://192.168.1.1/login`
- `http://google.com-secure-login.ml/verify`

**UPI test cases:**
- `upi://pay?pa=merchant@upi&pn=Shop&am=500` (safe)
- `upi://pay?pa=fake@xyz&am=9999` (suspicious)

---

## 🗺️ Roadmap

- [ ] Webcam live scanning in browser
- [ ] Deploy to Render / Railway for public demo
- [ ] Mobile app (Flutter)
- [ ] WHOIS domain age check
- [ ] Integration with NPCI verified merchant registry
- [ ] Support for regional languages (Hindi, Tamil, Telugu)

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👩‍💻 Author

**Purohit Sangeetha**

- GitHub: [@purohitsangeetha112-droid](https://github.com/purohitsangeetha112-droid)
- Project Link: [https://github.com/purohitsangeetha112-droid/QuishGuard](https://github.com/purohitsangeetha112-droid/QuishGuard)

---

## 🙏 Acknowledgments

- Kaggle Phishing URL Dataset by [Datta Teja](https://www.kaggle.com/dattatejaofficial)
- Indian cyber security research on quishing
- Open source community (Flask, scikit-learn, OpenCV, Chart.js)

---

<div align="center">

**⭐ If this project helped you, please give it a star!**

Made with ❤️ in India

</div>
