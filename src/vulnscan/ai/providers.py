"""各 AI プロバイダへの最小限の呼び出し。遅延 import で、使うものだけ依存を要求する。

Claude は公式 anthropic SDK、Gemini / OpenAI は REST（httpx）で呼ぶ。
"""

from __future__ import annotations

from .base import AIConfig, Complete

TIMEOUT = 120


def make(config: AIConfig) -> Complete:
    if config.provider == "claude":
        return _claude(config)
    if config.provider == "gemini":
        return _gemini(config)
    if config.provider == "openai":
        return _openai(config)
    raise ValueError(f"未対応のプロバイダです: {config.provider}")


def _claude(config: AIConfig) -> Complete:
    try:
        import anthropic
    except ImportError as e:
        raise RuntimeError("Claude を使うには anthropic パッケージが必要です") from e
    client = anthropic.Anthropic(api_key=config.api_key())
    model = config.resolved_model()

    def complete(system: str, user: str, max_tokens: int) -> str:
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in resp.content if b.type == "text")

    return complete


def _httpx_post(url: str, payload: dict, headers: dict) -> dict:
    try:
        import httpx
    except ImportError as e:
        raise RuntimeError("この AI プロバイダを使うには httpx パッケージが必要です") from e
    with httpx.Client(timeout=TIMEOUT) as c:
        r = c.post(url, json=payload, headers=headers)
        r.raise_for_status()
        return r.json()


def _openai(config: AIConfig) -> Complete:
    key = config.api_key()
    model = config.resolved_model()

    def complete(system: str, user: str, max_tokens: int) -> str:
        data = _httpx_post(
            "https://api.openai.com/v1/chat/completions",
            {
                "model": model,
                "max_completion_tokens": max_tokens,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        )
        return data["choices"][0]["message"]["content"]

    return complete


def _gemini(config: AIConfig) -> Complete:
    key = config.api_key()
    model = config.resolved_model()

    def complete(system: str, user: str, max_tokens: int) -> str:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            f"?key={key}"
        )
        data = _httpx_post(
            url,
            {
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {
                    "maxOutputTokens": max_tokens,
                    "responseMimeType": "application/json",
                },
            },
            {"Content-Type": "application/json"},
        )
        parts = data["candidates"][0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts)

    return complete
