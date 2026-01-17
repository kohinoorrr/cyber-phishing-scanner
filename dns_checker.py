import dns.resolver
import time

def dns_check(domain):
    try:
        start = time.time()
        answers = dns.resolver.resolve(domain, "A", lifetime=2)
        end = time.time()

        ips = [str(ip) for ip in answers]
        response_time = round(end - start, 3)

        return {
            "status": "resolved",
            "ips": ips,
            "time": response_time
        }

    except dns.resolver.NXDOMAIN:
        return {"status": "nxdomain"}

    except dns.resolver.Timeout:
        return {"status": "timeout"}

    except Exception as e:
        return {"status": "error", "msg": str(e)}


# Testing
if __name__ == "__main__":
    print(dns_check("google.com"))
    print(dns_check("login-free-verification.xyz"))
