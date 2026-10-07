import json

import pytest

from vulnscan.ai import load_ai_config
from vulnscan.ai.base import AIConfig, advise, build_user_prompt, parse_response
from vulnscan.models import Finding


def f(rule="r", loc="https://app.example.com/x", sev="medium"):
    return Finding("nuclei", rule, rule, sev, "https://app.example.com/", loc)


def test_disabled_by_default():
    c = load_ai_config()
    assert c.provider == "none" and not c.enabled
    assert c.availability_error() == "AI 探索支援は無効（none）です"
    assert c.resolved_model() is None


def test_unknown_provider_rejected():
    with pytest.raises(ValueError, match="いずれか"):
        load_ai_config("llama")


def test_requires_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    c = load_ai_config("claude")
    assert c.enabled
    assert "ANTHROPIC_API_KEY" in c.availability_error()
    assert c.resolved_model() == "claude-opus-5-5"


def test_api_key_and_model_override(monkeypatch):
    monkeypatch.setenv("MYKEY", "x")
    c = AIConfig(provider="openai", model="gpt-5-mini", api_key_env="MYKEY")
    assert c.availability_error() is None
    assert c.resolved_model() == "gpt-5-mini"
    assert c.api_key() == "x"


def test_build_prompt_includes_findings():
    prompt = build_user_prompt("https://app.example.com/", [f()], ["https://app.example.com/x"], 5)
    assert "最大 5 件" in prompt
    assert "https://app.example.com/x" in prompt


def test_parse_response_variants():
    payload = {
        "hypotheses": [
            {
                "title": "他人の注文が見える恐れ",
                "area": "authorization",
                "severity": "high",
                "confidence": "medium",
                "location": "https://app.example.com/orders/123",
                "rationale": "連番IDが使われている",
                "verification": "別ユーザーのIDでアクセスする",
            },
            {"title": ""},  # タイトル無しは無視
        ]
    }
    hs = parse_response("```json\n" + json.dumps(payload, ensure_ascii=False) + "\n```")
    assert len(hs) == 1
    assert hs[0].severity == "high" and hs[0].area == "authorization"


def test_parse_response_bad_json():
    with pytest.raises(ValueError):
        parse_response("JSONではありません")


def test_advise_with_fake_provider(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    captured = {}

    def fake(system, user, max_tokens):
        captured["system"] = system
        return json.dumps(
            {
                "hypotheses": [
                    {
                        "title": "権限昇格の可能性",
                        "area": "privilege_escalation",
                        "severity": "critical",
                        "confidence": "low",
                        "rationale": "管理APIが露出",
                        "verification": "一般権限で叩く",
                        "location": "https://app.example.com/admin/api",
                    }
                ]
            }
        )

    c = load_ai_config("claude")
    hs = advise(c, "https://app.example.com/", [f()], ["https://app.example.com/x"], complete=fake)
    assert len(hs) == 1
    fnd = hs[0].to_finding("https://app.example.com/")
    assert fnd.tool == "ai" and fnd.severity == "critical"
    assert "人手での確認が必要" in fnd.description
    assert "対象システムへアクセスできず" in captured["system"]


def test_advise_disabled_raises():
    with pytest.raises(RuntimeError, match="無効"):
        advise(load_ai_config(), "t", [], [], complete=lambda *a: "{}")


def test_max_items_caps(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    many = {"hypotheses": [{"title": f"h{i}", "severity": "low"} for i in range(50)]}
    c = AIConfig(provider="claude", max_items=3)
    hs = advise(c, "t", [], [], complete=lambda *a: json.dumps(many))
    assert len(hs) == 3
