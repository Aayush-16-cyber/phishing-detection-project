import pandas as pd
import joblib
import re
import tldextract
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# --------------------------------
# Load Updated Dataset
# --------------------------------
file_path = r"E:\CAPSTONE\Phishing_Detection_Project\dataset\cleaned_phishing_dataset.csv"
df = pd.read_csv(file_path)

# --------------------------------
# Feature Extraction Functions
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

    return features

# Apply feature extraction
feature_data = df['url'].apply(extract_features)
features_df = pd.DataFrame(list(feature_data))

X = features_df
y = df['label']

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Retrain Model
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Save Updated Model
joblib.dump(model, r"E:\CAPSTONE\Phishing_Detection_Project\model\phishing_model.pkl")

print("Model retrained and updated successfully!")