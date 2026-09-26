import ipaddress
from urllib.parse import urlparse


def classify_host(host):
    if not host:
        return None

    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"


def extract_url_host(url):
    if not url:
        return {
            "host": None,
            "host_type": None,
        }

    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
    except ValueError:
        return {
            "host": None,
            "host_type": None,
        }

    if not host:
        return {
            "host": None,
            "host_type": None,
        }

    host = host.lower()

    return {
        "host": host,
        "host_type": classify_host(host),
    }


if __name__ == "__main__":
    test_urls = [
        "http://123.135.74.52:51067/i",
        "https://malicious.example/payload",
        "https://Example.COM:8443/test",
        "http://[2001:db8::1]/payload",
        "",
        "not-a-valid-url",
    ]

    for test_url in test_urls:
        result = extract_url_host(test_url)

        print(f"URL: {test_url}")
        print(f"Host: {result['host']}")
        print(f"Host type: {result['host_type']}")
        print()