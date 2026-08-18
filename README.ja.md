# netdiag-mcp

[English](README.md) | 日本語

オンデマンドのネットワーク診断MCPサーバーです。DNS参照（DNSSEC ADビット確認込み）・ping・`mtr`ベースの経路レポート・TCPポート疎通確認・HTTPステータス/リダイレクト確認・TLS証明書確認・WHOISを1本にまとめています。

「〇〇に繋がらない」「DNS反映されたか」といった問い合わせの下調べを、踏み台サーバーへ都度SSHして`dig`/`ping`/`curl`を打つ代わりに済ませることを狙っています。

## ツール一覧

| ツール | 用途 |
|---|---|
| `dns_lookup` | `dig`によるDNSレコード参照（A/AAAA/MX/TXT/NS/CNAME/SOA/PTR/CAA）。特定リゾルバ指定も可 |
| `dnssec_check` | 検証済みリゾルバへ問い合わせてADビットの有無を確認する。素の`dig`でRRSIGが見えてもそれだけではDNSSEC検証済みとは言えないため、これが唯一の確実な確認方法 |
| `ping_host` | ICMP ping（countは1〜10にクランプ） |
| `traceroute_path` | `mtr --report`によるホップ単位の経路/ロスレポート（固定サイクル数、連続実行ではない） |
| `tcp_port_check` | TCPポートの開閉確認（単純なsocket connect、ポートスキャンではない） |
| `http_check` | URLへHEAD/GETしステータス・リダイレクトチェーン・レイテンシを報告 |
| `tls_cert_check` | 提示されたTLS証明書のsubject/issuer/有効期限/SANを報告 |
| `whois_lookup` | ドメインのWHOIS参照 |
| `health_check` | バージョンと、ラップしている各バイナリ（`dig`/`ping`/`mtr`/`whois`）がPATH上にあるかどうか |

すべて読み取り専用・単一ターゲットのみ（バッチ/一括スイープ機能なし）です。運用者が手で打つ疎通確認コマンドの薄いラッパーという位置づけで、`nmap`的な多ホスト/多ポートへの探索は意図的にスコープ外にしています。複数対象への能動的なプローブは影響範囲が異なる別の判断・承認フローが必要な行為だからです。

`tcp_port_check`・`http_check`・`tls_cert_check`はPython自身のsocket/ssl/httpxスタックを使い、`nc`/`curl`/`openssl`へシェルアウトしません。そのため`dig`/`ping`/`mtr`/`whois`のいずれかが入っていない（あるいは全く入っていない）ホストでもこの3つは動作します（`health_check`はどのバイナリが無いかを報告しますが、サーバー全体は落としません）。

## セットアップ

### 1. システム依存パッケージ

`dns_lookup`・`dnssec_check`・`ping_host`・`traceroute_path`・`whois_lookup`はそれぞれ`dig`・`ping`・`mtr`・`whois`にシェルアウトします。使いたいものだけ入れてください。

```bash
# Debian/Ubuntu
sudo apt install dnsutils iputils-ping mtr-tiny whois
```

### 2. インストール

```bash
pip install netdiag-mcp
# または
uv tool install netdiag-mcp
```

### 3. Claude Code（手動登録）

```bash
claude mcp add netdiag -- netdiag-mcp
```

必須の環境変数はありません。

## CLI

```bash
netdiag-mcp --version   # バージョン表示
netdiag-mcp --check     # ラップしているバイナリの有無を報告（全部あればexit 0）
```

## セキュリティ上の注意

- 外部バイナリの呼び出しは常にargvリスト渡し（シェル文字列を組み立てない）なので、引数がシェル構文として解釈される余地がありません
- ホスト名/IP・ポート番号はサイズ/範囲を検証してからしか使いません。ツール入力はLLM駆動＝敵対的とみなす、という他のツール呼び出し面と同じ扱いです
- `tcp_port_check`は1回の呼び出しにつき1つのhost:portのみ接続します。ループや範囲指定の引数は意図的に存在しません

## License

MIT
