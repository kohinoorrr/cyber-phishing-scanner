import joblib

model = joblib.load("phishing_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

def ai_predict(url):
    X = vectorizer.transform([url])
    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0][prediction]

    return {
        "prediction": "Phishing" if prediction == 1 else "Safe",
        "confidence": round(probability * 100, 2)
    }

# Test
if __name__ == "__main__":
    print(ai_predict("https://google.com"))
    print(ai_predict("http://login-secure-update.xyz"))
