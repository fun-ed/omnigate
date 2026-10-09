# 設定檔使用方式

OmniGate 使用單站 Webfile 格式。語法參考 Caddyfile，但不是完整 Caddyfile，不支援巢狀區塊、include、import 或多站設定。

## 範例

| 檔案 | 用途 |
|---|---|
| [http-example.Webfile](http-example.Webfile) | HTTP 與內建首頁，預設 `:8080` |
| [google-https-example.Webfile](google-https-example.Webfile) | 選用 Google ACME、HTTPS、HTTP/3 與憑證更新 |
| [proxy-example.Webfile](proxy-example.Webfile) | 兩個 upstream 的健康檢查與 round-robin |
| [websocket-example.Webfile](websocket-example.Webfile) | 自訂 `8443` port 的 WS／WSS proxy |
| [production-example.Webfile](production-example.Webfile) | Google HTTPS／HTTP3 設定範本 |
| [cloudflared-example.Webfile](cloudflared-example.Webfile) | Cloudflare Tunnel 的 HTTP-only origin 範本 |

使用 Cloudflare 範本前，先將 `public_url`、upstream URL 和 `trusted_proxies` 改成自己的環境值。只有在確認 socket peer 是可信 connector 後才能信任 forwarded metadata。公開 Webfile 不應包含密碼、EAB、私鑰或本機私密設定。

從來源目錄編譯並使用 HTTP 範例：

```sh
go build -o omnigate .
./omnigate -config config/http-example.Webfile
```

`example.com`、`admin@example.com` 和 `your-project-id` 等為範例佔位值，使用前請換成自己控制的網域、信箱與 Google Cloud project。Proxy 範例的 `9001`、`9002` upstream 必須已啟動，且 `GET /healthz` 回傳 2xx；否則 `/readyz` 與應用路徑會回傳 `503`。

根目錄的 [`Webfile.example`](../Webfile.example) 和 [`Webfile.websocket.example`](../Webfile.websocket.example) 保留一般 Webfile 用法。建立新設定時參考本目錄範例，不要將含有密碼或私密路徑的設定提交到版本控制。

## 優先序與路徑

設定優先序為程式預設值、Webfile、明確指定的 CLI flag。

```sh
./omnigate -config config/http-example.Webfile -http 127.0.0.1:8090 -rate 0
```

這個例子覆蓋 listen address 與 rate，其他欄位保留 Webfile 設定。`root`、`cert_dir` 的相對路徑以程序目前工作目錄為基準，不是設定檔所在目錄。

設定不會熱更新。修改後需在相同工作目錄、環境變數及設定下重新啟動。重啟會中斷長連線；升級操作需先安排服務中斷與回復方式。

## 格式

```text
example.com:8443 {
    http :8080
    http3 :8443
    tls google admin@example.com
    accept_tos on
    google_setup on
    cert_dir .certs
    rate_limit 10 20
    health_check /healthz 10s
    reverse_proxy http://127.0.0.1:9001 http://127.0.0.1:9002
}
```

- `:8080 {` 表示 HTTP-only 站點，不啟用 TLS。
- `example.com {` 設定憑證 DNS hostname，HTTPS 預設 `:443`。HTTP 仍預設 `:8080`，需要 `http :80` 或外部 TCP 80 轉送才能接受 ACME HTTP-01。
- `example.com:8443 {` 同時指定 TLS hostname 與 HTTPS listen port。
- `https` 可覆蓋站台標頭的 HTTPS port；`http3` 獨立指定 UDP address。
- 字串含空白時使用雙引號。`#` 開始註解。未知、重複或巢狀 directive 會讓啟動失敗。

## Directive

| Directive | 格式與預設 |
|---|---|
| `http` | `http <host:port>`，預設 `:8080` |
| `https` | `https <host:port>`，預設 `:443`，只在有 hostname 時啟用 |
| `http3` | `http3 <host:port>`，預設停用，需要 TLS，使用 UDP |
| `tls` | `tls google <email>`，指定 ACME email，不會自行接受 TOS |
| `accept_tos` | `accept_tos on` 或 `off`，預設 `off` |
| `google_setup` | `google_setup on` 或 `off`，預設 `off` |
| `google_project` | `google_project <project-id>`，仍會確認 project 可存取及 API 啟用 |
| `acme_directory` | `acme_directory <https-url>`，預設 Google production |
| `cert_dir` | `cert_dir <path>`，預設 `.certs`，保存私密 account key 與 certificate key |
| `root` | `root <path>`，預設不啟用 file hosting，路徑必須存在 |
| `basic_auth` | `basic_auth <user> env:<VARIABLE>`，只接受環境變數，不接受明文密碼 |
| `reverse_proxy` | `reverse_proxy <upstream> ...`，支援 HTTP／HTTPS／WS／WSS URL |
| `health_check` | `health_check <path> <interval>`，預設 `/healthz 10s` |
| `rate_limit` | `rate_limit <requests-per-second> <burst>`，預設 `10 20`，`0 20` 停用限流 |
| `public_url` | `public_url <https-origin>`，預設空；固定 canonical URL，拒絕 userinfo、query、fragment 與非根路徑 |
| `https_redirect` | `https_redirect on` 或 `off`，預設 `off`；解析後的 scheme 為 HTTP 時，應用路徑回 301 至 `public_url`，保留 path／query；HTTP origin 缺少有效 trusted `X-Forwarded-Proto` 時仍判為 HTTP；health path 不 redirect |
| `trusted_proxies` | `trusted_proxies <CIDR> ...`，預設空；只有 socket peer 位於明確列出的 CIDR 時才信任 forwarded metadata |
| `client_ip_header` | `client_ip_header CF-Connecting-IP` 或 `X-Real-IP`，預設空；需有 `trusted_proxies`，只接受單一合法 IP |
| `private_cache` | `private_cache on` 或 `off`，預設 `off`；應用 response 設為 `private, no-store`，不能清除 Cloudflare 已 cache 的 object |
| `hsts_max_age` | `hsts_max_age <seconds>`，預設 `0`；0 關閉，HTTPS response 才設定 HSTS，最大兩年 |
| `frame_options` | `SAMEORIGIN`、`DENY` 或 `off`，預設空；設定或移除 `X-Frame-Options` |
| `referrer_policy` | `strict-origin-when-cross-origin`、`no-referrer` 或 `off`，預設空 |
| `max_body_bytes` | `max_body_bytes <bytes>`，預設 `0`；0 關閉，未知長度 body 以串流限制，超限回 413 |
| `access_log` | `access_log on` 或 `off`，預設 `off`；記錄安全 request metadata，包括由 origin transport 判定的 `origin_scheme`，不記 path、query、credentials、body 或 username |

Body limit 不預讀完整 request。已知 `Content-Length` 超限會在 proxy 前拒絕；未知長度限制 handler／proxy 實際讀取的 bytes，觸發超限時映射為 413。若 handler 不讀 body 或 upstream 提早回應，不會為了檢查而讀完剩餘 body。未知長度可能已轉送部分內容，後端仍需處理不完整 upload；proxy 不自動 retry。

Cloudflare redirect 與 cache 需分別配置。Go origin 的 `private_cache` 無法讓 edge 既有 HIT 失效；hostname-scoped HTTPS rule、cache bypass 與 scoped purge 操作見 [Cloudflare guide](../docs/cloudflare.md)。CLI 對應旗標及完整預設值見 [實作規格](../docs/specs.md)。

## Basic Auth

在環境中提供非空密碼，再啟用以下 directive。不要把真實密碼寫進範例、shell history、Git 或 curl 的 argv。

```text
basic_auth admin env:WEB_HTTP_AUTH_PASSWORD
```

`curl --user admin https://example.com/` 會互動詢問密碼。公網必須使用 HTTPS。密碼不會轉送 upstream；`/healthz`、`/readyz` 不要求認證。

若透過 CLI `-auth-user` 覆蓋 username，密碼來源改為 `WEB_HTTP_AUTH_PASSWORD`，不沿用 Webfile 自訂的環境變數名稱。

## Google 初次設定

`google_setup on` 會依序確認網域、email 與 TOS，必要時詢問是否安裝 gcloud，並檢查既有 active login。已登入時跳過 `gcloud init`；只有沒有 active login 才執行互動 init。之後列出可存取的 project，再確認指定 project 與 Public CA API 啟用。

首次註冊需要可用 Python、Google 登入與相關 IAM 權限。程式不自動建立 project、授予 IAM 權限或安裝 Python。新 ACME 帳戶需要 EAB；取得後先與 account key 原子保存至私密 `cert_dir/state.json`，檔案權限為 `0600`、新目錄權限為 `0700`，再註冊。不顯示原始值，不寫入 Webfile、log 或公開 root。

保存 `.certs`。帳戶註冊後，重新啟動與續期不再安裝／初始化 gcloud，也不重新申請 EAB。每個快取目錄只供一個程序使用。

Production 與 staging 使用不同的 `cert_dir`。Staging 憑證不受一般瀏覽器信任。

```text
acme_directory https://dv.acme-v02.test-api.pki.goog/directory
cert_dir .certs-staging
```

詳細限制與安全回復方式見 [維護說明](../docs/maintenance.md)。v0.1.0 未驗證真實 Google 憑證簽發。

## HTTP/3 與 WebSocket

HTTPS 使用 TCP，HTTP/3 使用 UDP。同一個數字 port 可以同時綁定 TCP 與 UDP，但防火牆必須分別允許。Alt-Svc 廣告設定的 UDP listener port；若外部 UDP port 不同，需在轉送層修正廣告，目前沒有獨立 external-port 設定。

WS／WSS 使用 HTTP/1.1 Upgrade。HTTPS frontend 可使用 `wss://example.com:8443/socket`。Upstream `ws://` 對應 HTTP，`wss://` 對應 HTTPS，健康檢查仍使用 HTTP(S)。WSS upstream 必須提供作業系統信任的憑證，程式不會關閉 TLS 驗證。

開啟 `http3` 不代表支援 HTTP/3 WebSocket extended CONNECT。限流只套用到 WS handshake，不計算升級後的每個 frame。

## File hosting 與 proxy 共存

設定 `root` 後，`/static/` 提供檔案；沒有 upstream 時，`/` 也提供 root 內檔案。目錄需要 `index.html`，不列出目錄內容。沒有首頁且沒有 upstream 時，`/` 回傳內建 HTML。

有 upstream 時，除 health endpoints 與 `/static/` 外，其餘路徑交給 proxy。隱藏路徑與 root 外 symlink 不對外提供。`/healthz`、`/readyz` 是保留的本機端點，不會 proxy 到 upstream。

## Production 範本

`cloudflared-example.Webfile` 和 `production-example.Webfile` 是需先審閱和修改的範本，不是已驗收的部署設定。Cloudflare 範本啟用 HTTP-only origin 的 canonical redirect、可信 proxy metadata、private no-store、HSTS、frame/referrer headers 與 safe access log。Body limit 預設為 0，直到部署者確認 upload policy。使用 forwarded scheme 或 `CF-Connecting-IP` 前，確認 trusted CIDR 符合實際連到 origin 的 socket peer。

Google 範本需替換網域、project ID 與 ACME email；執行 Google setup 可能呼叫 gcloud、啟用 API 或取得 EAB。不要把真實設定、密碼或私鑰放入範例或版本控制。Cloudflare edge redirect、connector metadata、cache bypass 與 cache purge 需分別設定和驗收，見 [Cloudflare guide](../docs/cloudflare.md)。

預設 Basic Auth 密碼環境變數為 `WEB_HTTP_AUTH_PASSWORD`。Google EAB 環境變數 `GOOGLE_ACME_EAB_KID` 和 `GOOGLE_ACME_EAB_HMAC` 也維持原名以支援既有環境。完整啟動與備份說明見 [docs/production.md](../docs/production.md)。
