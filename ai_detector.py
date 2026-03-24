import joblib
from feature_extractor import extract_features
import pandas as pd

# Load the new Random Forest Model
model = joblib.load("phishing_rf_model.pkl")

def ai_predict(url):
    # 1. Extract the raw numerical features from the string
    features = extract_features(url)
    
    # 2. Format it into the DataFrame format expected by sklearn Random Forest
    columns = ["length", "dots", "hyphens", "ats", "slashes", "has_ip", "domain_len", "entropy"]
    X = pd.DataFrame([features], columns=columns)
    
    # 3. Predict probability
    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0][prediction]

    return {
        "prediction": "Phishing" if prediction == 1 else "Safe",
        "confidence": round(probability * 100, 2)
    }

# Test
if __name__ == "__main__":
    print(f"google.com -> {ai_predict('https://google.com')}")
    print(f"Malicious Login -> {ai_predict('http://login-secure-update.xyz')}")
    print(f"Raw IP Spam -> {ai_predict('http://192.168.1.1/a8v9s9r9s')}")
