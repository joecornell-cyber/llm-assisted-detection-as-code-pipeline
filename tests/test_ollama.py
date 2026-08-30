import requests

OLLAMA_URL = "http://192.168.87.1:11434/api/generate"

payload = {
    "model": "gpt-oss:20b",
    "prompt": "Reply with exactly: Python can reach Ollama",
    "stream": False,
}

response = requests.post(OLLAMA_URL, json=payload, timeout=120)
response.raise_for_status()

data = response.json()

print(data["response"])
