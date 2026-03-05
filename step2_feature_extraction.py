import pandas as pd
import re
import tldextract

# --------------------------------
# Load Cleaned Dataset
# --------------------------------
file_path = r"E:\CAPSTONE\Phishing_Detection_Project\dataset\cleaned_phishing_dataset.csv"
df = pd.read_csv(file_path)

# --------------------------------
# Feature Extraction Functions
# --------------------------------
def url_length(url):
    return len(url)

def count_dots(url):
    return url.count('.')

def count_slashes(url):
    return url.count('/')

def count_special_chars(url):
    return len(re.findall(r'[@?&=%-]', url))

def has_https(url):
    return 1 if url.startswith("https") else 0

def suspicious_words(url):
    keywords = ['login', 'verify', 'secure', 'account', 'bank', 'update']
    return sum(1 for word in keywords if word in url.lower())

def extract_domain_length(url):
    ext = tldextract.extract(url)
    return len(ext.domain)

# --------------------------------
# Apply Feature Extraction
# --------------------------------
df['url_length'] = df['url'].apply(url_length)
df['dots'] = df['url'].apply(count_dots)
df['slashes'] = df['url'].apply(count_slashes)
df['special_chars'] = df['url'].apply(count_special_chars)
df['https'] = df['url'].apply(has_https)
df['suspicious_words'] = df['url'].apply(suspicious_words)
df['domain_length'] = df['url'].apply(extract_domain_length)

# --------------------------------
# Final Dataset for ML
# --------------------------------
X = df.drop(columns=['url'])
print(X.head())

# Save feature dataset
output_path = r"E:\CAPSTONE\Phishing_Detection_Project\dataset\featured_phishing_dataset.csv"
X.to_csv(output_path, index=False)

print("\nFeature extraction completed!")
print("Saved as featured_phishing_dataset.csv")