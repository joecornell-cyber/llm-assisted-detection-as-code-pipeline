import os

import requests


class OllamaClient:
    def __init__(self):
        self.url = os.environ.get(
            "OLLAMA_URL",
            "http://192.168.87.1:11434/api/generate"
        )

        self.model = os.environ.get(
            "OLLAMA_MODEL",
            "gpt-oss:20b"
        )

    def generate(self, prompt):
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        response = requests.post(
            self.url,
            json=payload,
            timeout=180,
        )

        response.raise_for_status()

        data = response.json()

        return data["response"]
