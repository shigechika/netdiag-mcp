# Changelog

## [0.4.1](https://github.com/shigechika/netdiag-mcp/compare/v0.4.0...v0.4.1) (2026-08-22)


### Bug Fixes

* set explicit TLS minimum version in tls_cert_check ([#11](https://github.com/shigechika/netdiag-mcp/issues/11)) ([41cf6cd](https://github.com/shigechika/netdiag-mcp/commit/41cf6cdaf5a005cbbaadff1c7c6d7d2bb76ddf3f))

## [0.4.0](https://github.com/shigechika/netdiag-mcp/compare/v0.3.0...v0.4.0) (2026-08-20)


### Features

* package the server as a Claude Code plugin ([#7](https://github.com/shigechika/netdiag-mcp/issues/7)) ([9d56cfa](https://github.com/shigechika/netdiag-mcp/commit/9d56cfa73144765ca6d6e7b64b4cca2ebb793be6))

## [0.3.0](https://github.com/shigechika/netdiag-mcp/compare/v0.2.0...v0.3.0) (2026-08-19)


### Features

* add live smoke test (scripts/smoke_test.py) ([#5](https://github.com/shigechika/netdiag-mcp/issues/5)) ([1f78da7](https://github.com/shigechika/netdiag-mcp/commit/1f78da7200d14ffcfb4963b2412850c9713c7361))

## [0.2.0](https://github.com/shigechika/netdiag-mcp/compare/v0.1.0...v0.2.0) (2026-08-19)


### Features

* add DNS-over-TLS and DNS-over-HTTPS support to dns_lookup/dnssec_check ([61d10b4](https://github.com/shigechika/netdiag-mcp/commit/61d10b497fb4521f98ad008a543fd4c7ffd637e9))
* initial netdiag-mcp scaffold ([62ecbdf](https://github.com/shigechika/netdiag-mcp/commit/62ecbdfe3048279239f50264d92f3f98d8dfc8f8))


### Bug Fixes

* ping_host deadline handling, IPv6 ping on macOS; add asn_lookup ([624a055](https://github.com/shigechika/netdiag-mcp/commit/624a055b0e024638f118ae2460244732cf893fab))
* use [project.optional-dependencies] instead of [dependency-groups] ([#3](https://github.com/shigechika/netdiag-mcp/issues/3)) ([0e56227](https://github.com/shigechika/netdiag-mcp/commit/0e562277b6aaf87cf80a87840c6d8adcadbc51a6))
