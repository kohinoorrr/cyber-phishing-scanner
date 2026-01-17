from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from detector import analyze_url
import os

app = Flask(__name__)
CORS(app)

# Serve homepage
@app.route("/")
def home():
    return send_from_directory(os.getcwd(), "index.html")

# API endpoint
@app.route("/check", methods=["POST"])
def check_url():
    data = request.json
    url = data.get("url")
    # ✅ Auto-fix missing scheme
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url


    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = analyze_url(url)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
