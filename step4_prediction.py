import joblib
import re
import tldextract
import pandas as pd

# --------------------------------
# Load Trained Model
# --------------------------------
model_path = r"E:\CAPSTONE\Phishing_Detection_Project\model\phishing_model.pkl"
model = joblib.load(model_path)

# --------------------------------
# Feature Extraction Functions
# (Same as Step 2 – VERY IMPORTANT)
# --------------------------------
def extract_features(url):
    features = {}

    features['url_length'] = len(url)
    features['dots'] = url.count('.')
    features['slashes'] = url.count('/')
    features['special_chars'] = len(re.findall(r'[@?&=%-]', url))
    features['https'] = 1 if url.startswith("https") else 0

    keywords = ['login', 'verify', 'secure', 'account', 'bank', 'update']
    features['suspicious_words'] = sum(
        1 for word in keywords if word in url.lower()
    )

    ext = tldextract.extract(url)
    features['domain_length'] = len(ext.domain)

    return pd.DataFrame([features])

# --------------------------------
# Real-Time Prediction
# --------------------------------
while True:
    url = input("\nEnter a URL (or type 'exit'): ")

    if url.lower() == 'exit':
        break

    features_df = extract_features(url)
    prediction = model.predict(features_df)[0]

    if prediction == 1:
        print("🚨 PHISHING WEBSITE DETECTED!")
    else:
        print("✅ SAFE WEBSITE")