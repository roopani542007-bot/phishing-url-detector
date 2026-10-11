# 🛡️ PhishGuard AI — Phishing URL Detector

A portfolio-friendly machine-learning web application that analyzes URL characteristics and estimates whether a URL is likely legitimate or suspicious.

## What makes it interesting?
- Machine learning using Random Forest
- Cybersecurity-focused feature extraction
- Interactive Flask web interface
- Risk score and explainable URL features
- Clean, responsive dashboard

## Tech Stack
- Python
- Flask
- Pandas
- Scikit-learn
- HTML/CSS

## Run locally
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open the address shown in the terminal, usually `http://127.0.0.1:5000`.

## Example URLs
Try:
- `https://github.com`
- `https://www.python.org`
- `http://secure-login-verify.example.com/account`

## Disclaimer
This is an educational portfolio project using a small synthetic demonstration dataset. It should not be used as a real-world phishing protection system.
