import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# --------------------------------
# Load Featured Dataset
# --------------------------------
file_path = r"E:\CAPSTONE\Phishing_Detection_Project\dataset\featured_phishing_dataset.csv"
df = pd.read_csv(file_path)

X = df.drop(columns=['label'])
y = df['label']

# --------------------------------
# Train-Test Split
# --------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# --------------------------------
# Models
# --------------------------------
models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Decision Tree": DecisionTreeClassifier(),
    "Random Forest": RandomForestClassifier(n_estimators=100)
}

best_model = None
best_accuracy = 0

# --------------------------------
# Train & Evaluate Models
# --------------------------------
for name, model in models.items():
    print(f"\nTraining {name}...")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    print(f"{name} Accuracy: {accuracy:.4f}")
    print(classification_report(y_test, y_pred))

    if accuracy > best_accuracy:
        best_accuracy = accuracy
        best_model = model

# --------------------------------
# Save Best Model
# --------------------------------
joblib.dump(best_model, r"E:\CAPSTONE\Phishing_Detection_Project\model\phishing_model.pkl")

print("\nBest model saved as phishing_model.pkl")
print("Best Accuracy:", best_accuracy)