import re
from urllib.parse import urlparse
import requests
from dns_checker import dns_check
from ssl_checker import check_ssl
from ai_detector import ai_predict



SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure",
    "account", "bank", "free", "gift", "confirm"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd"
]

def get_domain(url):
    parsed = urlparse(url)
    return parsed.netloc.replace("www.", "")

def count_redirects(url):
    try:
        r = requests.head(url, allow_redirects=True, timeout=3)
        return len(r.history)
    except:
        return 0

def analyze_url(url):
    score = 0
    reasons = []

    # ---------- URL RULES ----------
    if len(url) > 75:
        score += 1
        reasons.append("URL is very long")

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 2
        reasons.append("IP address used instead of domain")

    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            score += 1
            reasons.append(f"Suspicious keyword found: {word}")

    if url.count('-') > 4 or url.count('.') > 4:
        score += 1
        reasons.append("Too many special characters")

    parsed = urlparse(url)
    if parsed.scheme != "https":
        score += 1
        reasons.append("Not using HTTPS")

    # ---------- SUBDOMAIN CHECK ----------
    domain = get_domain(url)
    dot_count = domain.count(".")
    if dot_count >= 4:
        score += 2
        reasons.append("Too many subdomains")

    # ---------- URL SHORTENER ----------
    for short in URL_SHORTENERS:
        if short in domain:
            score += 3
            reasons.append("URL shortener detected")

    # ---------- NUMBER HEAVY URL ----------
    digit_count = sum(c.isdigit() for c in url)
    if digit_count > 6:
        score += 1
        reasons.append("Too many digits in URL")

    # ---------- REDIRECT CHECK ----------
    redirects = count_redirects(url)
    if redirects >= 3:
        score += 2
        reasons.append(f"Multiple redirects detected ({redirects})")

    # ---------- DNS CHECK ----------
    dns_result = dns_check(domain)

    if dns_result["status"] == "resolved":
        reasons.append(f"DNS resolved ({dns_result['time']}s)")
        if dns_result["time"] > 1:
            score += 1
            reasons.append("DNS response slow")

    elif dns_result["status"] == "timeout":
        score += 2
        reasons.append("DNS timeout")

    elif dns_result["status"] == "nxdomain":
        score += 3
        reasons.append("Domain does not exist")

    else:
        score += 1
        reasons.append("DNS error")


        # ---------- SSL CHECK ----------
    ssl_result = check_ssl(domain)

    if ssl_result["status"] == "valid":
        reasons.append("Valid SSL certificate")

    else:
        score += 2
        reasons.append("Invalid or missing SSL certificate")


    # ---------- FINAL RESULT ----------
    if score >= 7:
        status = "Phishing"
    elif score >= 4:
        status = "Suspicious"
    else:
        status = "Safe"
        # ---------- AI PREDICTION ----------
    ai_result = ai_predict(url)

    reasons.append(f"AI Prediction: {ai_result['prediction']} ({ai_result['confidence']}%)")

    if ai_result["prediction"] == "Phishing":
        score += 2

    return {
        "url": url,
        "domain": domain,
        "dns": dns_result,
        "redirects": redirects,
        "score": score,
        "status": status,
        "reasons": reasons,
        "ai": ai_result,
    }
