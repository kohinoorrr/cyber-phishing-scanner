import ssl
import socket

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                return {
                    "status": "valid",
                    "issuer": cert.get("issuer"),
                    "expires": cert.get("notAfter")
                }

    except Exception as e:
        return {
            "status": "invalid",
            "error": str(e)
        }


# Test
if __name__ == "__main__":
    print(check_ssl("google.com"))
    print(check_ssl("login-free-verification.xyz"))
