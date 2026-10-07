"""AI 助言レイヤーの本体（プロバイダ非依存）。"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass

from ..models import Finding, normalize_severity

PROVIDERS = ("none", "claude", "gemini", "openai")

# プロバイダごとの既定モデルと API キーの環境変数名
DEFAULTS = {
    "claude": ("claude-opus-5-5", "ANTHROPIC_API_KEY"),
    "gemini": ("gemini-2.5-pro", "GEMINI_API_KEY"),
    "openai": ("gpt-5", "OPENAI_API_KEY"),
}

# LLM へは「助言のみ・対象へアクセスしない」ことを明示する
SYSTEM_PROMPT = (
    "あなたは許可された自社資産に対する脆弱性診断の結果を読み、"
    "人手で確認すべき探索的テストの観点を助言するセキュリティアナリストです。"
    "自動スキャナ（nmap / nuclei / ZAP）が見逃しやすい領域、特に認可の不備、"
    "業務ロジックの欠陥、権限昇格、情報漏えいの観点を重視します。"
    "重要な制約: あなたは対象システムへアクセスできず、新たな攻撃や通信も行いません。"
    "与えられた結果の範囲内で、検証すべき仮説と手順だけを日本語で提案してください。"
    "推測であることを明示し、確実でないものは confidence を low にしてください。"
    "出力は指定された JSON のみ。"
)

Complete = Callable[[str, str, int], str]  # (system, user, max_tokens) -> text


@dataclass(frozen=True)
class AIConfig:
    provider: str = "none"
    model: str | None = None
    api_key_env: str | None = None
    max_items: int = 10

    @property
    def enabled(self) -> bool:
        return self.provider != "none"

    def resolved_model(self) -> str | None:
        if not self.enabled:
            return None
        return self.model or DEFAULTS[self.provider][0]

    def api_key(self) -> str | None:
        if not self.enabled:
            return None
        env = self.api_key_env or DEFAULTS[self.provider][1]
        return os.environ.get(env) or None

    def availability_error(self) -> str | None:
        """使える状態かを確認し、問題があれば理由を返す。"""
        if not self.enabled:
            return "AI 探索支援は無効（none）です"
        if self.provider not in DEFAULTS:
            return f"未知の AI プロバイダです: {self.provider}"
        if not self.api_key():
            env = self.api_key_env or DEFAULTS[self.provider][1]
            return f"API キーが環境変数 {env} に設定されていません"
        return None


@dataclass
class Hypothesis:
    title: str
    severity: str
    area: str
    rationale: str
    verification: str
    location: str = ""
    confidence: str = "low"

    def to_finding(self, target: str) -> Finding:
        note = (
            f"[AIによる探索観点の提案 / 確度: {self.confidence}。人手での確認が必要です]\n"
            f"観点: {self.area}\n{self.rationale}"
        )
        return Finding(
            tool="ai",
            rule_id=f"ai-{self.area}",
            title=self.title,
            severity=normalize_severity(self.severity),
            target=target,
            location=self.location or target,
            description=note,
            remediation=f"確認手順: {self.verification}",
        )


def load_ai_config(
    provider: str = "none", model: str | None = None, api_key_env: str | None = None
) -> AIConfig:
    provider = (provider or "none").lower()
    if provider not in PROVIDERS:
        raise ValueError(f"AI プロバイダは {PROVIDERS} のいずれかです: {provider}")
    return AIConfig(provider=provider, model=model, api_key_env=api_key_env)


def _summarize_findings(findings: list[Finding], limit: int = 60) -> list[dict]:
    rows = []
    for f in findings[:limit]:
        rows.append(
            {
                "tool": f.tool,
                "severity": f.severity,
                "title": f.title,
                "location": f.location,
            }
        )
    return rows


def build_user_prompt(target: str, findings: list[Finding], urls: list[str], max_items: int) -> str:
    data = {
        "target": target,
        "scanned_urls": urls[:100],
        "findings": _summarize_findings(findings),
    }
    schema = {
        "hypotheses": [
            {
                "title": "日本語の短い見出し",
                "area": "authorization | business_logic | privilege_escalation | "
                "info_disclosure | authentication | other",
                "severity": "critical|high|medium|low|info",
                "confidence": "high|medium|low",
                "location": "関連する URL（任意）",
                "rationale": "なぜ疑わしいか（日本語）",
                "verification": "人手での確認手順（日本語）",
            }
        ]
    }
    return (
        "次の診断結果を踏まえ、人手で確認すべき探索的テストの観点を"
        f"最大 {max_items} 件、重要なものから提案してください。\n\n"
        f"診断結果:\n{json.dumps(data, ensure_ascii=False, indent=2)}\n\n"
        f"出力する JSON の形式:\n{json.dumps(schema, ensure_ascii=False, indent=2)}"
    )


def parse_response(text: str) -> list[Hypothesis]:
    data = _extract_json(text)
    out: list[Hypothesis] = []
    for raw in data.get("hypotheses", []):
        if not raw.get("title"):
            continue
        out.append(
            Hypothesis(
                title=str(raw["title"]),
                severity=normalize_severity(raw.get("severity")),
                area=str(raw.get("area", "other")),
                rationale=str(raw.get("rationale", "")),
                verification=str(raw.get("verification", "")),
                location=str(raw.get("location", "")),
                confidence=str(raw.get("confidence", "low")).lower(),
            )
        )
    return out


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        text = text[4:].strip() if text.lower().startswith("json") else text.strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("AI 応答に JSON が見つかりません")
    return json.loads(text[start : end + 1])


def advise(
    config: AIConfig,
    target: str,
    findings: list[Finding],
    urls: list[str],
    complete: Complete | None = None,
) -> list[Hypothesis]:
    """AI に助言を求め、仮説の一覧を返す。complete を渡すとそれを使う（テスト用）。"""
    err = config.availability_error()
    if err:
        raise RuntimeError(err)
    fn = complete or _provider_complete(config)
    user = build_user_prompt(target, findings, urls, config.max_items)
    text = fn(SYSTEM_PROMPT, user, 4000)
    return parse_response(text)[: config.max_items]


def _provider_complete(config: AIConfig) -> Complete:
    from . import providers

    return providers.make(config)
