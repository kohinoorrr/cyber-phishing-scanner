import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import joblib

# Small sample dataset (you can expand later)
data = {
    "url": [
        "https://google.com",
        "https://facebook.com",
        "https://amazon.com",
        "http://login-secure-update.xyz",
        "http://free-gift-card-login.com",
        "http://192.168.1.5/verify",
        "http://paypal.account.verify.security.xyz"
    ],
    "label": [0,0,0,1,1,1,1]  # 0 = Safe, 1 = Phishing
}

df = pd.DataFrame(data)

X = df["url"]
y = df["label"]

vectorizer = TfidfVectorizer()
X_vec = vectorizer.fit_transform(X)

model = LogisticRegression()
model.fit(X_vec, y)

# Save model
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("✅ AI model trained and saved.")
