import json
import os

import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkClient:
    def __init__(self):
        self.base_url = os.environ["SPLUNK_URL"].rstrip("/")
        self.token = os.environ["SPLUNK_TOKEN"]

        # Lab uses Splunk's self-signed certificate.
        self.verify_tls = (
            os.environ.get("SPLUNK_VERIFY_TLS", "false").lower() == "true"
        )

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}"
        })

    def search(self, spl_query):
        url = f"{self.base_url}/services/search/v2/jobs/export"

        response = self.session.post(
            url,
            data={
                "search": spl_query,
                "output_mode": "json",
            },
            verify=self.verify_tls,
            timeout=60,
        )

        response.raise_for_status()

        results = []

        # Splunk export returns one JSON object per line.
        for line in response.text.splitlines():
            if not line.strip():
                continue

            data = json.loads(line)

            if "result" in data:
                results.append(data["result"])

        return results
