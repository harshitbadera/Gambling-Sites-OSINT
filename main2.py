import tldextract
import dns.resolver
from ipwhois import IPWhois

print("=" * 60)
print("DOMAIN INFRASTRUCTURE LOOKUP")
print("=" * 60)

domain = input("\nEnter Website/Domain: ").strip()

# Clean input
domain = domain.replace("https://", "")
domain = domain.replace("http://", "")
domain = domain.split("/")[0]

# Extract Main Domain
ext = tldextract.extract(domain)
main_domain = f"{ext.domain}.{ext.suffix}"

print("\n" + "=" * 60)
print("RESULTS")
print("=" * 60)

print(f"\nMain Domain: {main_domain}")

resolver = dns.resolver.Resolver()

# Use Google + Cloudflare DNS
resolver.nameservers = [
    "8.8.8.8",
    "1.1.1.1"
]

# -------------------------
# IPv4 Addresses
# -------------------------

ipv4_list = []

try:
    answers = resolver.resolve(
        main_domain,
        "A",
        lifetime=10
    )

    for answer in answers:
        ipv4_list.append(answer.to_text())

except Exception:
    pass

print("\nIPv4 Addresses:")

if ipv4_list:
    for ip in ipv4_list:
        print(" -", ip)
else:
    print("Not Found")

# -------------------------
# IPv6 Addresses
# -------------------------

ipv6_list = []

try:
    answers = resolver.resolve(
        main_domain,
        "AAAA",
        lifetime=10
    )

    for answer in answers:
        ipv6_list.append(answer.to_text())

except Exception:
    pass

print("\nIPv6 Addresses:")

if ipv6_list:
    for ip in ipv6_list:
        print(" -", ip)
else:
    print("Not Found")

# -------------------------
# Hosting Provider
# -------------------------

print("\nHosting Information:")

if ipv4_list:

    try:

        ip = ipv4_list[0]

        obj = IPWhois(ip)

        result = obj.lookup_rdap()

        network = result.get(
            "network",
            {}
        )

        print(
            "Hosting Provider:",
            network.get("name")
        )

        print(
            "Country:",
            network.get("country")
        )

        print(
            "ASN:",
            result.get("asn")
        )

        print(
            "ASN Description:",
            result.get(
                "asn_description"
            )
        )

    except Exception as e:

        print(
            "Lookup Error:",
            e
        )

print("\n" + "=" * 60)
print("DONE")
print("=" * 60)
