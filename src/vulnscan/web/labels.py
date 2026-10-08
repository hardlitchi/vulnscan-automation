"""画面に表示するやさしい日本語のラベル。"""

from __future__ import annotations

SEVERITY = {
    "critical": {"label": "緊急", "guide": "すぐに対応してください（当日中が目安）"},
    "high": {"label": "高", "guide": "早めに対応してください（1週間以内が目安）"},
    "medium": {"label": "中", "guide": "計画的に対応してください（1か月以内が目安）"},
    "low": {"label": "低", "guide": "余裕があるときに対応してください"},
    "info": {"label": "参考", "guide": "対応は不要です（状況把握のための情報）"},
}

PROFILE = {
    "passive": {
        "label": "かんたん診断",
        "desc": "動いているサービスにほとんど負担をかけない軽い確認です。本番環境でも使えます。",
    },
    "standard": {
        "label": "標準診断（おすすめ）",
        "desc": "よく知られた脆弱性を幅広く確認します。攻撃的な検査は行いません。",
    },
    "active": {
        "label": "詳細診断",
        "desc": "実際の攻撃に近い検査を含みます。検証環境でのみ使ってください。",
    },
}

TOOL = {
    "nmap": "公開されているサービスの確認（nmap）",
    "nuclei": "よく知られた脆弱性の確認（nuclei）",
    "webcheck": "Webアプリの基本診断（内蔵。セキュリティヘッダ・Cookie・入力の反射など。URL を指定した対象のみ）",
    "zap": "Webサイトの動作確認（OWASP ZAP、URL を指定した対象のみ）",
    "ai": "AIによる探索的診断の観点提案（要人手確認）",
}

RUN_STATUS = {
    "running": "実行中",
    "completed": "完了",
    "partial": "一部のチェックが失敗",
}

JOB_STATUS = {
    "queued": "順番待ち",
    "running": "実行中",
    "done": "完了",
    "failed": "失敗",
}
