import math
import re
from urllib.parse import urlparse

def extract_features(url):
    """
    Extract mathematical properties from the URL string.
    These features form the backbone of the Random Forest model.
    """
    # 1. URL Length
    url_length = len(url)

    # 2. Number of special characters
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_ats = url.count('@')
    num_slashes = url.count('/')
    
    # 3. Detect IP Addresses hiding in URL
    parsed = urlparse(url)
    domain_str = parsed.netloc
    has_ip = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", domain_str) else 0

    # 4. Length of the domain specifically
    domain_length = len(domain_str)

    # 5. Shannon Entropy of the raw URL (Detects random alphanumeric spam strings)
    entropy = calculate_entropy(url)
    
    # Return as an ordered list for the ML model
    return [
        url_length, 
        num_dots, 
        num_hyphens, 
        num_ats, 
        num_slashes,
        has_ip,
        domain_length,
        entropy
    ]

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x)))/len(text)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

# Simple test function
if __name__ == "__main__":
    test_urls = ["https://google.com", "http://login.paypal.support.verify.com", "http://192.168.1.1/a8v9s9r9s"]
    for u in test_urls:
        print(f"{u} -> {extract_features(u)}")
