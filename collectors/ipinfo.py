import os

import requests
from dotenv import load_dotenv


load_dotenv()


IPINFO_LITE_URL = "https://api.ipinfo.io/lite"


def get_ipinfo_token():
    token = os.getenv("IPINFO_TOKEN")

    if not token:
        raise RuntimeError(
            "IPINFO_TOKEN is missing from the .env file."
        )

    return token


def get_ip_enrichment(ip_address):
    token = get_ipinfo_token()

    response = requests.get(
        f"{IPINFO_LITE_URL}/{ip_address}",
        params={
            "token": token,
        },
        timeout=15,
    )

    response.raise_for_status()

    data = response.json()

    return {
        "provider": "IPinfo",
        "asn": data.get("asn"),
        "as_name": data.get("as_name"),
        "as_domain": data.get("as_domain"),
        "country_code": data.get("country_code"),
        "country": data.get("country"),
        "continent_code": data.get("continent_code"),
        "continent": data.get("continent"),
    }