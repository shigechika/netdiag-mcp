# リファレンス

## ツール

### `health_check`

引数なし。`{status, service, version, binaries, missing}`を返す。`status`は
`dig`/`ping`/`mtr`/`whois`が全てPATH上にあれば`"healthy"`、1つでも欠けていれば
`"degraded"`（該当ツールは呼び出し時にエラーになるが、サーバー自体は起動し続ける）。

### `dns_lookup(hostname, record_type="A", resolver=None, transport="plain")`

`dig`によるDNSレコード解決。`record_type`: `A`/`AAAA`/`MX`/`TXT`/`NS`/`CNAME`/
`SOA`/`PTR`/`CAA`。`resolver`を渡すとホスト既定ではなく特定のネームサーバーへ
問い合わせる（特定リゾルバへの反映確認等）。`transport`: `"plain"`（UDP/TCP 53、
既定）・`"dot"`（DNS over TLS、853）・`"doh"`（DNS over HTTPS、443）。BIND 9.18
以降の`dig`が必要——古い`dig`は`dot`/`doh`を平文DNSへ黙ってフォールバックせず、
即座に拒否する。

### `dnssec_check(hostname, resolver="1.1.1.1", transport="plain")`

検証済みリゾルバへ問い合わせADビットの有無を確認。`transport`は上記と同様——
53番ポートが介入されている懸念がある場合、平文DNSと暗号化トランスポートでの
検証結果を比較するのに使う。

### `ping_host(host, count=4)`

ICMP ping。`count`は1〜10にクランプ。macOSではIPv6リテラルを`ping6`へ自動振り分け
（macOSの`ping`はIPv6を拒否するため）。Linuxでは`ping`が両方式に対応し`ping6`は
使わない。

### `traceroute_path(host, cycles=3)`

`mtr --report`によるホップ単位の経路/損失レポート（固定サイクル、常時実行では
ない）。`cycles`は1〜10にクランプ。`mtr-packet`の`cap_net_raw`権限が必要——無い
場合はサーバーをクラッシュさせず`ToolError`でクリーンに失敗する。

### `tcp_port_check(host, port, timeout=5.0)`

TCPポートの開放確認——単一の`host:port`への単純なsocket接続で、ポートスキャンでは
ない。ループやレンジ引数は意図的に持たない。

### `http_check(url, timeout=5.0)`

URLへHEAD/GETしステータス・リダイレクトチェーン・レイテンシを報告。

### `tls_cert_check(host, port=443)`

ホストが提示する証明書を取得しsubject/issuer/有効期限/SANを報告。SNIホスティング
/CDN配下のオリジンへIPアドレス直接指定するとハンドシェイクが失敗しうる——正常な
TLSの挙動でツールの不具合ではない（[index](index.ja.md#設計上の注意点)参照）。

### `whois_lookup(domain)`

ドメインのWHOIS参照。

### `asn_lookup(target)`

Team Cymruのwhoisサービスによる、IPのAS番号・国コード逆引き、またはAS番号
（`AS15169`や`15169`）の組織情報取得。APIキー・GeoIP DB不要。IPリテラルまたは
AS番号のみ受け付ける（ホスト名は不可、名前しか無い場合は先に`dns_lookup`で解決
すること）。

## エラー

全ツールが`ValueError`（不正な入力）と`ToolError`（ラップしているコマンドの
失敗）を捕捉し、例外を投げる代わりに`"error: ..."`という文字列を返す。呼び出し側
は常に文字列を受け取れる。

## CLI

```bash
netdiag-mcp --version   # バージョン表示
netdiag-mcp --check     # ラップしているバイナリの有無を報告（全て揃っていれば終了コード0）
```

`--check`は`dig`/`ping`/`mtr`/`whois`のいずれかが欠けていると非0で終了する——
デプロイスクリプトで、サーバーが静かに劣化する前に早期失敗させるのに使える。

## セキュリティ上の注意点

- 外部バイナリの呼び出しは全てargvリストで行い（シェル文字列は使わない）、
  ツール引数がシェル構文へ抜け出すことはできない
- ホスト名/IP・ポート引数は使用前に検証・サイズ/範囲クランプされる——ツール入力は
  モデル駆動であり、他のtool-calling面と同様に信頼しないものとして扱う
- 全ツールが読み取り専用で、このサーバーには書き込み・変更系ツールが1つも無い
