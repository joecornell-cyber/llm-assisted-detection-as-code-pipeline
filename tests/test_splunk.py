import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_URL = os.environ["SPLUNK_URL"]
SPLUNK_TOKEN = os.environ["SPLUNK_TOKEN"]

headers = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}"
}

search = "search index=windows | head 5"

response = requests.post(
    f"{SPLUNK_URL}/services/search/v2/jobs/export",
    headers=headers,
    data={
        "search": search,
        "output_mode": "json",
    },
    verify=False,
    timeout=60,
)

response.raise_for_status()

print(response.text)
