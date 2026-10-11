from flask import Flask, render_template, request
import re
from urllib.parse import urlparse
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

app = Flask(__name__)

FEATURES = [
    "url_length", "has_ip", "has_at", "has_hyphen", "dot_count",
    "subdomain_count", "uses_https", "suspicious_words",
    "has_shortener", "has_port"
]

def extract_features(url):
    clean = url.strip()
    parsed = urlparse(clean if "://" in clean else "http://" + clean)
    host = parsed.netloc.split("@")[-1].split(":")[0]
    words = ["login", "verify", "update", "secure", "account", "bank",
             "signin", "password", "confirm", "wallet"]

    return {
        "url_length": len(clean),
        "has_ip": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
        "has_at": int("@" in clean),
        "has_hyphen": int("-" in host),
        "dot_count": host.count("."),
        "subdomain_count": max(0, host.count(".") - 1),
        "uses_https": int(parsed.scheme.lower() == "https"),
        "suspicious_words": sum(w in clean.lower() for w in words),
        "has_shortener": int(any(x in host.lower() for x in
            ["bit.ly", "tinyurl.com", "t.co", "is.gd"])),
        "has_port": int(parsed.port is not None) if parsed.hostname else 0
    }

def make_training_data():
    samples = [
        ("https://www.google.com", 0), ("https://github.com", 0),
        ("https://www.microsoft.com", 0), ("https://www.python.org", 0),
        ("https://www.wikipedia.org", 0), ("https://www.amazon.com", 0),
        ("https://www.linkedin.com", 0), ("https://www.apple.com", 0),
        ("https://stackoverflow.com", 0), ("https://www.nasa.gov", 0),
        ("http://secure-login-verify.example.com/account", 1),
        ("http://account-update.example.com/verify", 1),
        ("http://192.168.1.25/login", 1),
        ("http://fake-bank-login.example.com", 1),
        ("http://user@secure-update.example.com", 1),
        ("http://password-confirm-wallet.example.com", 1),
        ("http://signin-account-verify.example.com", 1),
        ("http://tinyurl.com/abc123", 1),
        ("http://login-secure-account.example.com:8080", 1),
        ("http://verify-user.example.com/password", 1),
    ]
    rows = []
    for url, label in samples:
        f = extract_features(url)
        rows.append([f[k] for k in FEATURES] + [label])
        # small variations for a more useful demo dataset
        if label == 1:
            variant = url + "?session=12345"
            f = extract_features(variant)
            rows.append([f[k] for k in FEATURES] + [label])
    return pd.DataFrame(rows, columns=FEATURES + ["label"])

df = make_training_data()
X = df[FEATURES]
y = df["label"]
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)
model = RandomForestClassifier(n_estimators=150, random_state=42)
model.fit(X_train, y_train)
MODEL_ACCURACY = accuracy_score(y_test, model.predict(X_test))

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    details = []
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            f = extract_features(url)
            prediction = model.predict(pd.DataFrame([f])[FEATURES])[0]
            probability = model.predict_proba(pd.DataFrame([f])[FEATURES])[0][1]
            result = {
                "label": "Suspicious / Phishing Risk" if prediction else "Likely Legitimate",
                "risk": round(probability * 100),
                "safe": prediction == 0
            }
            details = [
                ("HTTPS", "Yes" if f["uses_https"] else "No"),
                ("IP address used", "Yes" if f["has_ip"] else "No"),
                ("Suspicious keywords", str(f["suspicious_words"])),
                ("Subdomains", str(f["subdomain_count"])),
                ("URL length", str(f["url_length"]))
            ]
    return render_template(
        "index.html", result=result, details=details,
        url=url, accuracy=round(MODEL_ACCURACY * 100, 1)
    )

if __name__ == "__main__":
    app.run(debug=True)
