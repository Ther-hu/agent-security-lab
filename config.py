# backend: "ollama" | "openai" | "deepseek"
BACKEND = "ollama"
OLLAMA_MODEL = "qwen3:8b"
OPENAI_MODEL = "gpt-4o-mini"
OPENAI_API_KEY = ""        # 用云端时填
OPENAI_BASE_URL = ""       # deepseek 填 https://api.deepseek.com
TEMPERATURE = 0            # 实验统一用 0，保证可复现