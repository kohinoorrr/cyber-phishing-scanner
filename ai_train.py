import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
from feature_extractor import extract_features

# 1. Expanded Sample Dataset for Training
# 0 = Safe, 1 = Phishing
data = {
    "url": [
        "https://google.com",
        "https://facebook.com",
        "https://amazon.com",
        "https://github.com/torvalds/linux",
        "https://wikipedia.org",
        "https://apple.com/iphone",
        "https://youtube.com/watch?v=dQw4w9WgXcQ",
        "https://microsoft.com",
        "https://netflix.com",
        "https://reddit.com/r/programming",
        "https://stackoverflow.com/questions",
        "https://linkedin.com/feed",
        "https://medium.com/@user/article",
        "https://twitter.com/elonmusk",
        "https://instagram.com/p/12345",
        "https://twitch.tv/ninja",
        "https://discord.com/app",
        "https://spotify.com/playlist",
        "https://weather.com",
        "https://nytimes.com",
        
        # Phishing Examples
        "http://login-secure-update.xyz",
        "http://free-gift-card-login.com",
        "http://192.168.1.5/verify",
        "http://paypal.account.verify.security.xyz",
        "http://appleid-confirm-billing.com/login",
        "http://netflix-billing-update2024.net",
        "https://amazon-security-alert-center.co",
        "http://bankofamerica-urgent-notice.biz",
        "http://chase-online-verify-identity.ru",
        "http://10.0.0.1/admin/login.php",
        "http://steam-free-games-giveaway.tk",
        "http://discord-nitro-gift-claim.cn",
        "http://office365-login-portal-secure.info",
        "http://google-drive-shared-doc-view.com",
        "http://facebook-security-check-account.org",
        "http://instagram-copyright-appeal.net",
        "http://whatsapp-web-login-secure.biz",
        "http://172.16.254.1/auth",
        "http://wellsfargo-update-profile.ru",
        "http://yahoo-mail-verify-password.com",
    ],
    "label": [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # Safe
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1   # Phishing
    ]
}

df = pd.DataFrame(data)

# 2. Feature Extraction
print("⏳ Extracting mathematical features from URLs...")
features = []
for url in df["url"]:
    features.append(extract_features(url))

# Create a DataFrame of the extracted numerical features
X = pd.DataFrame(features, columns=["length", "dots", "hyphens", "ats", "slashes", "has_ip", "domain_len", "entropy"])
y = df["label"]

# 3. Model Training
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("🌲 Training Random Forest Classifier...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 4. Evaluation
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"🎯 Model Accuracy on Test Data: {accuracy * 100:.2f}%")

# 5. Save Model
joblib.dump(model, "phishing_rf_model.pkl")
print("✅ Advanced Random Forest model saved as 'phishing_rf_model.pkl'.")
