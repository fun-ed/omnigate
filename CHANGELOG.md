# 變更紀錄

## v0.1.0 · 2026-10-10

OmniGate 首次公開 release。原始碼位於 [github.com/fun-ed/omnigate](https://github.com/fun-ed/omnigate)。使用 Go 1.27.1 或更新版本，可執行 `go install github.com/fun-ed/omnigate@v0.1.0` 安裝。

### 功能

- 單站 HTTP 與 HTTPS server，支援 CLI flags 和單站 Webfile 設定。
- 選用 ACME 憑證管理，支援 HTTP-01、Google Public CA setup、EAB、私密憑證狀態、續期與憑證熱換。
- 選用 QUIC HTTP/3、Alt-Svc；停用 0-RTT。
- HTTP、HTTPS、WS 和 WSS reverse proxy upstream，支援健康檢查與 round-robin 選取。
- 透過 HTTP/1.1 Upgrade proxy WebSocket。
- 選用 Basic Auth、per-peer rate limiting、靜態檔案、liveness 與 readiness endpoints。
- 選用 trusted-proxy handling、canonical HTTPS redirect、private cache headers、HSTS、frame 與 referrer headers、request-body limit，以及安全 access log。

### 已知限制

- 本 release 未驗證真實 Google 憑證簽發。Google setup 可能執行互動式 gcloud、project、API 及 EAB 操作；操作人員需逐項檢查並授權。
- v0.1.0 binary 未執行長時間 soak、fault injection 或新的壓力測試。Repository 中的歷史數據來自較早的 `web-http` build，不是 OmniGate v0.1.0 benchmark。
- Server shutdown 不會 drain 已升級的 WebSocket 連線。不支援 HTTP/3 extended CONNECT。
- 尚無 CSP enforcement、設定 hot reload、metrics endpoint、response cache、DNS-01、wildcard 憑證、跨程序 rate limiter 或跨程序 HA。
- `max_body_bytes` 預設為 `0`，代表 request body 不限大小，除非明確設定上限。
- `private_cache` 只設定 origin headers，無法使 Cloudflare edge 已快取的 object 失效或 purge。
- 預設 listener 與 Webfile 行為維持相容；選用的 hardening directives 預設未啟用。

本 repository 尚未指定 license，也未包含 license file。
