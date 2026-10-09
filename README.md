# OmniGate

OmniGate 是以 Go 撰寫的單站 HTTP／HTTPS server，支援選用 ACME 憑證、HTTP/3、reverse proxy、WebSocket proxy、靜態檔案，以及 CLI 或 Webfile 設定。

原始碼：[github.com/fun-ed/omnigate](https://github.com/fun-ed/omnigate) · [Releases](https://github.com/fun-ed/omnigate/releases)

首個版本為 v0.1.0，需要 Go 1.27.1 或更新版本。

## 功能

| 範圍 | 行為 |
|---|---|
| HTTP 與 HTTPS | HTTP 預設監聽 `:8080`。設定網域後可啟用 ACME HTTPS 與 HTTP-to-HTTPS redirect。也可使用可信 HTTP origin redirect 與固定 canonical URL。 |
| ACME | 可選擇 Google Public CA setup。支援 HTTP-01、EAB、私密憑證狀態、續期及憑證熱換。 |
| HTTP/3 | 選用 QUIC listener、自訂 UDP port 與 Alt-Svc；停用 0-RTT。 |
| Reverse proxy | 多個 HTTP(S) 或 WS(S) upstream、round-robin、健康檢查與恢復。不會重送失敗的應用程式 request。 |
| WebSocket | 透過 HTTP/1.1 Upgrade 使用 WS 或 WSS。不支援 HTTP/3 extended CONNECT。 |
| Basic Auth | 選用環境變數密碼。OmniGate 不會將 edge `Authorization` header 轉送 upstream。 |
| Rate limiting | 預設依 peer IP 限流。設定可信 proxy CIDR 與單一 client-IP header 後，可依 client IP 分 bucket。 |
| 靜態檔案 | 選用檔案 root、`/static/` 路徑、`index.html`，不提供目錄列表。 |
| Health checks | `/healthz` 回報存活狀態；`/readyz` 回報已設定的 upstream 是否健康。兩者略過認證與限流。 |
| 設定 | 單站 Webfile 或 CLI flags。明確指定的 CLI flags 覆蓋 Webfile。另有選用 redirect、proxy trust、cache、安全標頭、request body limit 與安全 access log。 |

## 快速開始

使用 Go 安裝 v0.1.0：

```sh
go install github.com/fun-ed/omnigate@v0.1.0
omnigate -http 127.0.0.1:8080
```

或取得原始碼並使用 HTTP 範例：

```sh
git clone https://github.com/fun-ed/omnigate.git
cd omnigate
go build -o omnigate .
./omnigate -config config/http-example.Webfile
```

檢查內建首頁與健康端點：

```sh
curl -i http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/readyz
./omnigate -help
```

使用 proxy 範例前，先啟動文件中提到的 upstream。每個 upstream 的 `GET /healthz` 都必須回傳 2xx，才會被視為 ready。

### Basic Auth

範例從環境變數讀取密碼。不要把密碼寫入 Webfile、命令列參數、shell history、Git 或 log。可在 Bash 相容的 shell 互動輸入密碼：

```sh
printf 'Basic Auth password: '
read -r -s WEB_HTTP_AUTH_PASSWORD
printf '\n'
export WEB_HTTP_AUTH_PASSWORD
omnigate -config config/proxy-example.Webfile
```

公開網路上的 Basic Auth 必須搭配 HTTPS。`curl --user admin https://example.com/` 會互動詢問密碼，不會將密碼放在命令列。既有 `WEB_HTTP_AUTH_PASSWORD`、`GOOGLE_ACME_EAB_KID` 與 `GOOGLE_ACME_EAB_HMAC` 環境變數名稱維持支援。

### Google HTTPS 與 HTTP/3

Google 範例為選用功能。使用前需要自己控制的網域、同意 ACME 服務條款、Google Cloud 權限，以及可供 HTTP-01 驗證使用的公網 TCP port 80。執行前請檢查並修改 `config/google-https-example.Webfile`。`google_setup on` 可能啟動互動式 gcloud 設定，或要求進行 Google API 與 EAB 操作。請勿以佔位值直接執行。

v0.1.0 未驗證真實 Google 憑證簽發。此版本不宣稱已設定 Google 帳戶、project、API、DNS 記錄或公用憑證。

## 文件

- [Webfile 範例與設定](config/README.md)
- [實作規格與預設值](docs/specs.md)
- [架構與 ACME 流程](docs/architecture.md)
- [建置、部署與維護](docs/maintenance.md)
- [Production 部署指引](docs/production.md)
- [Cloudflare Tunnel、redirect 與 edge cache](docs/cloudflare.md)
- [除錯](docs/debug.md)
- [負載測試工具與重跑方式](scripts/README.md)
- [歷史負載測試報告](reports/2026-10-08-load-test.md)
- [變更紀錄](CHANGELOG.md)

Repository 也包含有日期的開發計畫與驗證紀錄。這些紀錄保留原有名稱與來源，不代表 v0.1.0 release 驗證結果。

## 測試

```sh
mise exec go@1.27.1 -- go test -race -count=1 -cover ./...
mise exec go@1.27.1 -- go vet ./...
mise exec -- python -m unittest discover -s scripts -p 'test_*.py' -v
```

Go tests 使用本機 ACME CA 等測試 fixture，不會登入 Google、變更 Google Cloud project 或向 Google 申請憑證。Python 工具測試與測試資料說明見 [scripts/README.md](scripts/README.md)。

## 歷史負載數據

下列負載測試早於 OmniGate 品牌與 v0.1.0 release。它記錄較早 `web-http` source 的測試，不得當作 v0.1.0 OmniGate binary 的 benchmark。本次 release 沒有執行新的壓力測試。

歷史測試使用 Go 1.27.1、Apple M4／Darwin arm64，只測 HTTP/1.1 內建首頁。四階段各 10 秒，concurrency 為 1、10、40、100，共完成 254,390 次成功 request，錯誤 0。Server RSS 取樣最高為 17.11 MiB。這是 client 與 server 共用主機的短時間 closed-loop 測試，不代表容量上限、保證的記憶體峰值、長期 soak 或與其他 server 的比較。精確命令、來源與 binary checksum、原始資料及圖表見[原始報告](reports/2026-10-08-load-test.md)。

![歷史 HTTP throughput](reports/charts/http-throughput.svg)

![歷史 server 記憶體取樣](reports/charts/http-memory.svg)

## 限制

OmniGate 是單程序、單站 server。沒有設定 hot reload、共享或跨程序 rate limiter、response cache、壓縮、metrics endpoint、DNS-01、wildcard 憑證或跨程序 HA。HTTP shutdown 不會排空已升級的 WebSocket 連線。沒有 CSP enforcement。`max_body_bytes` 預設為 `0`，未設定上限時 request body 不受限制。Origin 的 `private, no-store` headers 無法 purge 已存在 Cloudflare edge cache 的 object。不支援 HTTP/3 WebSocket extended CONNECT。

預設設定維持既有 HTTP listener、CLI 行為與 Webfile 行為；選用的 hardening directives 預設關閉。變更部署設定前，請先閱讀[實作規格](docs/specs.md)。

## 授權

此 repository 尚未指定 license，也沒有附加 license file。程式碼重用及再散布的條件尚未指定。
