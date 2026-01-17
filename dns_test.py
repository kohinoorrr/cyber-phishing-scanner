import dns.resolver
import time

domain = "google.com"

start = time.time()   # start timer
answers = dns.resolver.resolve(domain, "A")   # ask DNS for IP
end = time.time()     # end timer

print("Domain:", domain)
print("IP addresses:")

for ip in answers:
    print(" -", ip)

print("Response time:", round(end - start, 3), "seconds")
