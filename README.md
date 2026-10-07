# vulnscan-automation

自社で管理・所有する資産に対して、OSS スキャナ（nmap / nuclei / OWASP ZAP）による
脆弱性診断を自動実行し、結果を集約・差分化してレポートするツールです。

> **重要:** 本ツールは承認済みスコープ（`scope.yaml`）に含まれる対象以外には一切スキャンを
> 実行しません。第三者が所有・管理する資産を、所有者の書面による許可なく診断することは
> 不正アクセス禁止法等に抵触するおそれがあります。

## 特徴

- **スコープガード**: 承認 ID・承認者・期間・時間帯・許可プロファイル・除外対象を
  `scope.yaml` で管理。ドメインは名前解決後の IP も承認 CIDR 内か確認します。
  ツール実行の直前に毎回再判定し、キルスイッチで全診断を即停止できます。
- **プロファイル**: `passive` / `standard` / `active` の 3 段階で侵襲度を制御
  （nuclei の intrusive・dos・fuzz テンプレートは standard 以下で除外）。
- **正規化と差分**: 各ツールの結果を共通形式に変換し、前回との差分（新規・継続・解消）を出します。
- **誤検知管理**: 理由と期限付きで抑制（`suppressions.yaml`）。
- **監査ログ**: 判定結果と実行コマンドを JSON Lines で記録。
- **出力**: Markdown / JSON レポート、Slack 通知（任意）。

## 必要なもの

- Python 3.11 以上
- スキャナ: ローカルの `nmap` / `nuclei`、または Docker（`--docker` 指定時）
- ZAP は常に Docker イメージ `ghcr.io/zaproxy/zaproxy:stable` で実行します

## セットアップ

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp scope.example.yaml scope.yaml          # 対象と承認情報を記入
cp suppressions.example.yaml suppressions.yaml   # 任意
vulnscan scope validate -s scope.yaml
```

## 使い方

```bash
# 対象が診断可能かだけを確認（スキャンしない）
vulnscan scope check -s scope.yaml -t https://app.example.com/ -p standard

# 実行コマンドの確認（スキャンしない）
vulnscan scan -s scope.yaml -t https://app.example.com/ -p standard --dry-run

# 診断を実行
vulnscan scan -s scope.yaml -t https://app.example.com/ -p standard --docker

# scope.yaml に記載の URL・ドメインをすべて診断
vulnscan scan -s scope.yaml --all -p passive --docker
```

主なオプション:

| オプション | 説明 |
|---|---|
| `--tools nmap,nuclei,zap` | 実行するツール |
| `--profile passive\|standard\|active` | 侵襲度（承認で許可されたもののみ） |
| `--docker` | nmap / nuclei を Docker イメージで実行 |
| `--fail-on high` | high 以上の新規指摘があれば終了コード 1（CI 向け） |
| `--notify-min high` | Slack 通知の重大度下限（環境変数 `VULNSCAN_SLACK_WEBHOOK` を設定） |
| `--db` / `--out` / `--audit-log` | 保存先 |

終了コード: `0` 正常 / `1` `--fail-on` に該当 / `2` スコープ外の対象あり / `3` 設定エラー

レポートは `reports/<日時>/report.md` と `report.json` に出力されます。

## 定期実行（社内サーバ）

`deploy/` に systemd の service / timer の例があります。

```bash
sudo cp deploy/vulnscan.service deploy/vulnscan.timer /etc/systemd/system/
sudo systemctl enable --now vulnscan.timer
```

運用上の注意:

- 診断専用ホストで実行し、送信元 IP を監視チーム・WAF 管理者へ事前に共有してください
- `scope.yaml` は本リポジトリとは別の非公開リポジトリで管理し、変更はレビュー必須にしてください
- レポートには脆弱性の詳細が含まれます。保存先の権限を限定してください
- 緊急停止: `touch /var/run/vulnscan.stop`（`kill_switch_file` で指定したパス）
  または `VULNSCAN_KILL=1`

## 開発

```bash
pytest -q
ruff check . && ruff format --check .
```

設計の詳細は [docs/design.md](docs/design.md) を参照してください。
