import requests


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def get_cisa_kev():
    response = requests.get(CISA_KEV_URL, timeout=30)

    response.raise_for_status()

    data = response.json()

    return data


if __name__ == "__main__":
    kev_data = get_cisa_kev()

    print("Catalog title:", kev_data["title"])
    print("Catalog version:", kev_data["catalogVersion"])
    print("Number of vulnerabilities:", len(kev_data["vulnerabilities"]))