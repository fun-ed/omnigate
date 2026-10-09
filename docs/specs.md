# 實作規格

本文記錄目前程式已實作的行為，不把尚未實作的設定或營運方式當成產品保證。部署範例、開發計畫與 Cloudflare rollout 見 [config/README.md](../config/README.md)、[2026-10-09 hardening plan](../plan/2026-10-09-hardening.md)、[Cloudflare guide](cloudflare.md) 和 [improvement checklist](../plan/improvement.md)。負載測試結果見 [reports/2026-10-08-load-test.md](../reports/2026-10-08-load-test.md)。

## 範圍與啟動

服務只接受一個站台設定。預設只開 HTTP，監聽 `:8080`。設定 `-domain` 或 Webfile 網域站台後，啟動程序會配置 ACME，先監聽 HTTP，再取得或更新憑證，然後開啟 HTTPS。HTTP/3 必須明確設定，使用同一張 TLS 憑證與應用程式處理器。

Webfile 是本專案的精簡格式，不是完整 Caddyfile。檔案以 `hostname {` 或 `:port {` 開始，只能有一個站台區塊；每行一個 directive，可用雙引號包住含空白的字串，以 `#` 開始註解。directive 不得重複。命令列明確指定的旗標會覆蓋 Webfile 值；其餘值使用 Webfile 或預設值。密碼只從環境變數讀取。

## 命令列旗標

| 旗標 | 預設值 | 行為 |
| --- | --- | --- |
| `-config` | 空 | 載入單一站台 Webfile。 |
| `-http` | `:8080` | HTTP TCP 監聽位址。使用 HTTP-01 時，外部 CA 必須能連到公用 TCP 80。 |
| `-https` | `:443` | HTTPS TCP 監聽位址；只有啟用 `-domain` 時才會開啟。 |
| `-http3` | 空 | 設定後開啟 HTTP/3 UDP 監聽；需要 `-domain` 及有效的 `host:port`。 |
| `-domain` | 空 | 單一小寫 ASCII DNS 主機名稱，不支援 IP、萬用字元或大寫字母。國際化網域請用 punycode。 |
| `-email` | 空 | ACME 帳戶電子郵件。啟用 HTTPS 時必填。 |
| `-acme-directory` | `https://dv.acme-v02.api.pki.goog/directory` | ACME directory 的 HTTPS URL。 |
| `-cert-dir` | `.certs` | 私有 ACME 狀態目錄。同一目錄必須僅供一個服務程序使用，程式沒有跨程序鎖。 |
| `-accept-tos` | `false` | 明確接受 ACME 服務條款。 |
| `-setup-google` | `false` | 互動式 Google Cloud CLI 設定；只接受 Google production 或 staging directory，可能安裝 gcloud、執行登入初始化、啟用 API 並在首次註冊時取得 EAB。 |
| `-google-project` | 空 | Google setup 使用的專案 ID；必須是登入帳號可列出的有效專案。 |
| `-root` | 空 | 靜態檔案根目錄。 |
| `-upstreams` | 空 | 逗號分隔的 HTTP(S) 或 WS(S) upstream URL。 |
| `-health-path` | `/healthz` | 相對於 upstream URL 路徑的健康檢查路徑。可含 query。 |
| `-health-interval` | `10s` | upstream 健康檢查間隔。 |
| `-auth-user` | 空 | 啟用 HTTP Basic Authentication 的帳號；不能包含冒號。 |
| `WEB_HTTP_AUTH_PASSWORD` | 未設定 | CLI `-auth-user` 的 Basic Auth 密碼；Webfile `basic_auth` 可讀取 directive 指定的環境變數。 |
| `GOOGLE_ACME_EAB_KID` | 未設定 | 新 ACME registration 使用的 EAB key ID。 |
| `GOOGLE_ACME_EAB_HMAC` | 未設定 | 新 ACME registration 使用的 EAB HMAC。完整 env pair 優先，再使用 private cache 的完整 EAB，否則已啟用 Google setup 時向 Google 取得。只設定其中一項會失敗。新註冊前將完整 EAB 與 account key 原子保存至 private state；自訂 ACME directory 也須提供該 CA 的 EAB。 |
| `-rate` | `10` | 每個對端 IP 的請求速率，單位為次/秒。設為 `0` 關閉限制。 |
| `-burst` | `20` | 每個對端 IP 的速率桶容量。 |
| `-public-url` | 空 | 固定 HTTPS canonical origin，用於 redirect 與 proxy host；不採用 request `Host`。 |
| `-https-redirect` | `false` | 已判定為 HTTP 的應用路徑回 301；direct TLS 判為 HTTPS。HTTP origin 只有可信 peer 的單一合法 `X-Forwarded-Proto` 可改變 scheme；缺漏或無效值沿用 HTTP。需要 `-public-url`。 |
| `-trusted-proxies` | 空 | 逗號分隔的可信 proxy CIDR。空值表示不信任 forwarded metadata。 |
| `-client-ip-header` | 空 | `CF-Connecting-IP` 或 `X-Real-IP`；需設定 `-trusted-proxies`，並只接受一個合法 IP。 |
| `-private-cache` | `false` | 將應用回應的 cache policy 覆寫為 `private, no-store`，移除 shared-cache TTL headers。 |
| `-hsts-max-age` | `0` | HSTS 秒數；0 關閉，只在 HTTPS response 寫入，最大兩年。 |
| `-frame-options` | 空 | `SAMEORIGIN`、`DENY` 或 `off`。空值不修改 header。 |
| `-referrer-policy` | 空 | `strict-origin-when-cross-origin`、`no-referrer` 或 `off`。空值不修改 header。 |
| `-max-body-bytes` | `0` | 應用 request body 最大 bytes；0 關閉。 |
| `-access-log` | `false` | 記錄自產 request ID、method、status、duration、`origin_scheme`（由 Go origin transport 判定：TLS 為 `https`，明文為 `http`）與 completion 狀態；不代表公網 HTTPS scheme。 |

明確指定的 CLI flag 仍會覆蓋 Webfile。所有新增 hardening flag 預設關閉；Production Webfile 明確啟用其選定政策。

Rate limiter 以 peer IP 為預設 key。只有 peer 位於 `-trusted-proxies` CIDR 且 `-client-ip-header` 含單一合法 IP 時，才以該 client IP 計算 bucket；不展開 `X-Forwarded-For` chain。全程序最多保留 10,000 個 IP 的狀態，超出時新 IP 會被拒絕；每分鐘掃除閒置 10 分鐘以上的項目。

設定驗證會拒絕負值、非有限值或大於 `1e6` 的速率、低於 `1` 的 burst，以及非正的健康檢查間隔。設定 `-domain` 後，ACME directory 必須是 HTTPS URL，並須提供合法網域、email、非空的 `-https` 位址及 TOS 同意；啟用 HTTP/3 時須有網域及有效 UDP `host:port`。HTTP 位址不可為空，命令列不可有額外位置參數。

## Webfile directives

| Directive | 參數 | 預設值 | 說明 |
| --- | --- | --- | --- |
| 站台列 | `hostname {` 或 `:port {` | 無 | 只接受一個站台。網域列啟用 HTTPS；`hostname:port` 會將 HTTPS 位址設為該 port。以 `:port` 開始只設定 HTTP 位址。 |
| `http` | 一個位址 | `:8080` | HTTP TCP listener。 |
| `https` | 一個位址 | `:443` | HTTPS TCP listener。 |
| `http3` | 一個 UDP `host:port` | 關閉 | 啟用 HTTP/3；必須同時設定網域及 HTTPS。 |
| `tls` | `google <email>` | 關閉 | 設定 ACME 帳戶信箱。只有站台設定網域時才啟用 HTTPS，並要求接受 TOS。 |
| `accept_tos` | `on` 或 `off` | `off` | 記錄 ACME TOS 同意。 |
| `google_setup` | `on` 或 `off` | `off` | 啟用 Google Cloud CLI setup；若 cache 已有相符 registration，會略過 gcloud 操作。 |
| `google_project` | 一個專案 ID | 空 | Google setup 選用的專案。 |
| `acme_directory` | 一個 HTTPS URL | `https://dv.acme-v02.api.pki.goog/directory` | 指定 ACME directory。Google setup 只接受 Google production 或 staging directory。 |
| `cert_dir` | 一個路徑 | `.certs` | ACME 狀態與私鑰的持久目錄。 |
| `root` | 一個路徑 | 空 | 靜態檔案根目錄。 |
| `reverse_proxy` | 一個或多個 upstream URL | 空 | 使用空白分隔 upstream。允許 `http://`、`https://`、`ws://`、`wss://`，不允許 URL 帳密、query 或 fragment。 |
| `basic_auth` | `<username> env:<VARIABLE>` | 關閉 | 從指定環境變數讀取密碼；空值或明文密碼會使設定失敗。 |
| `rate_limit` | `<requests-per-second> <burst>` | `10 20` | 設定每 IP 限制。速率可設為 `0` 關閉。 |
| `health_check` | `<path> <duration>` | `/healthz 10s` | 設定 upstream 檢查路徑及間隔。路徑須是絕對 URL path，不可含主機、fragment 或 `//` 開頭。 |
| `public_url` | 一個 HTTPS origin URL | 空 | 固定 redirect 與 upstream external host；不接受 userinfo、query、fragment 或非根路徑。 |
| `https_redirect` | `on` 或 `off` | `off` | 已判定為 HTTP 的應用路徑回 301；direct TLS 優先。HTTP origin 只有可信 peer 的單一合法 `X-Forwarded-Proto` 可改變 scheme；缺漏或無效值沿用 HTTP。需要 `public_url`。Health path 不 redirect。 |
| `trusted_proxies` | 一個或多個 CIDR | 空 | Webfile 以空白分隔，CLI 以逗號分隔。只有 peer 在此範圍內時才信任 forwarded scheme 或 client IP。 |
| `client_ip_header` | `CF-Connecting-IP` 或 `X-Real-IP` | 空 | 只接受單一合法 IP；需要 `trusted_proxies`。 |
| `private_cache` | `on` 或 `off` | `off` | 將應用 response 設為 `private, no-store`，移除 origin shared-cache directives。不能清除已存在的 edge cache。 |
| `hsts_max_age` | 非負整數秒數 | `0` | 0 關閉；只在判定為 HTTPS 的 response 設定 HSTS，不自動加 `includeSubDomains` 或 `preload`。 |
| `frame_options` | `SAMEORIGIN`、`DENY` 或 `off` | 空 | 設定或移除 `X-Frame-Options`。 |
| `referrer_policy` | `strict-origin-when-cross-origin`、`no-referrer` 或 `off` | 空 | 設定或移除 `Referrer-Policy`。 |
| `max_body_bytes` | 非負整數 bytes | `0` | 0 關閉；在認證後限制應用 request body。未知長度 body 以串流方式限制，可能已有部分內容送到後端。 |
| `access_log` | `on` 或 `off` | `off` | 記錄自產 request ID、method、status、duration、`origin_scheme`（Go 收到請求時的 TLS／明文 transport）與 completion；不記 path、query、credentials、body 或 username。 |

例如設定語法可參考根目錄的 [`Webfile.example`](../Webfile.example) 和 [`Webfile.websocket.example`](../Webfile.websocket.example)。範例會啟用 Google setup；執行前要先檢查並替換網域、信箱及專案設定。

## 路由順序

### HTTP listener

啟用自動 HTTPS 時，HTTP handler 先處理下列路徑，再交給應用程式：

1. `/.well-known/acme-challenge/` 前綴只接受 GET。匹配目前 token 時回傳 challenge key authorization；不存在的 token 回 404，其他方法回 405。
2. `/healthz` 與 `/readyz` 不檢查 Host，也不做 HTTPS redirect。
3. 其餘請求需符合設定的網域，否則回 421。符合時回 308，將原路徑與 query 轉址到 HTTPS。

沒有設定網域時，HTTP listener 直接使用應用程式路由。

HTTP listener 在已設定 `domain` 時仍使用 ACME challenge handler 的既有 308 redirect，這與 HTTP-only origin 的 `https_redirect` 是不同設定。`https_redirect` 由 `edge_policy.go` 處理到達應用程式的請求，使用固定 `public_url`，直接 TLS 優先。HTTP origin 只採用可信 peer 的單一合法 `X-Forwarded-Proto`；缺漏或無效值沿用 HTTP scheme，因此啟用 redirect 時仍會回 301。它在限流與 Basic Auth 前處理應用路徑；健康端點略過 redirect。

### 應用程式路由

`/healthz` 與 `/readyz` 先於 Basic Auth 和速率限制處理。兩者只接受 GET、HEAD。`/healthz` 一律回 200；設定 upstream 時，`/readyz` 在沒有健康 upstream 時回 503，否則回 200。

其他路徑先經過每 IP 限流，再經過 Basic Auth，最後依序處理。若 `https_redirect on` 且解析後的 scheme 為 HTTP，redirect 會在限流及認證前結束 request。沒有有效 forwarded scheme 的 HTTP origin 仍按 HTTP 處理。

1. 設定 `root` 且路徑以 `/static/` 開頭時，從靜態根目錄提供檔案，即使也設定了 upstream。
2. 有 upstream 時，其餘路徑都轉送到 upstream。
3. 沒有 upstream、但設定 `root` 時，`/` 有 `index.html` 就提供該檔案；其他路徑由靜態檔案處理器提供。
4. 沒有 upstream 且 `root` 未設定或根目錄沒有 `index.html` 時，`/` 的 GET、HEAD 回內建 HTML，其他方法回 405。未設定 `root` 時，其他路徑回 404。

靜態檔案根目錄使用 `os.Root` 限制檔案存取範圍。檔名含隱藏路徑元件時不提供；目錄必須含 `index.html`，不列出目錄內容。

## HTTP 狀態與協定

| 情況 | 回應 |
| --- | --- |
| 健康端點方法不是 GET 或 HEAD | 405，並帶 `Allow: GET, HEAD`。 |
| 未通過 Basic Auth | 401，並帶 `WWW-Authenticate`。 |
| 超過每 IP 速率限制或 limiter 記憶體上限 | 429，帶 `Retry-After: 1`。 |
| `/readyz` 沒有健康 upstream，或沒有 upstream 可用 | 503。 |
| upstream 代理錯誤 | 502；request context 仍有效時，該 upstream 標記為不健康。 |
| HTTP-01 token 不存在、靜態檔案不存在或未配置路徑 | 404。 |
| HTTP 主機不符合啟用 TLS 的設定網域 | 421。 |
| `https_redirect on` 且解析後的 scheme 為 HTTP 的應用路徑 | 301 至固定 `public_url`，保留 escaped path 與 query；不使用 request `Host`。HTTP origin 沒有有效可信 `X-Forwarded-Proto` 時仍判為 HTTP。 |
| 應用 request 超過 `max_body_bytes` | 413。未知長度 body 可能已部分送到 handler 或 upstream，服務不會 retry。 |
| 內建首頁上的方法不是 GET 或 HEAD | 405。 |

錯誤設定不是 HTTP 400。設定解析或驗證失敗會在 listener 建立前讓程序退出。net/http 仍可能對格式錯誤的 HTTP 請求自行回應 400；代理 upstream 也可能回傳自己的狀態碼。

HTTPS 最低 TLS 版本為 1.2。HTTP/3 使用 QUIC、相同的憑證與應用程式 handler，並在 HTTPS 回應宣告 Alt-Svc；程式停用 QUIC 0-RTT。WebSocket 使用 HTTP/1.1 Upgrade，支援明文或 TLS frontend，以及 `ws://`、`wss://` upstream；不支援 HTTP/3 extended CONNECT。

## 安全邊界與未實作事項

- 服務只設定單一 DNS 網域，不支援萬用字元憑證。
- Basic Auth 密碼只能透過環境變數提供。成功驗證後，服務會從轉送請求移除 `Authorization`。
- upstream URL 不接受內嵌帳密、query 或 fragment。
- 靜態檔案不得逃離設定根目錄。請求路徑含隱藏元件時不提供，目錄不列出內容。不要在公開 root 中建立指向私密檔案的可見名稱 symlink。
- 只有 `trusted_proxies` CIDR 內的 peer 可提供可信的 `X-Forwarded-Proto`；`client_ip_header` 僅接受單一 `CF-Connecting-IP` 或 `X-Real-IP`。沒有設定時使用 socket peer IP，不信任 `X-Forwarded-For` chain。
- `private_cache` 將應用 response 設為 `private, no-store` 並移除 origin shared-cache headers；Cloudflare 已有 cache HIT 不會因此失效，需分別設定 edge bypass 或授權後 purge。
- Health response 一律 `private, no-store`。`hsts_max_age` 只在 HTTPS response 設 HSTS。Basic Auth 401 在 `private_cache` 啟用時也使用 `private, no-store`。
- Request access log 預設關閉；啟用後不記 path、query、Authorization、Cookie、body 或 username。沒有 metrics endpoint。
- ACME 狀態包含帳戶私鑰、憑證私鑰及註冊資料，必須限制目錄與檔案存取。
- 設定不支援 hot reload。HTTP server shutdown 不會排空已 hijack 的 WebSocket 連線。
- 同一個 `cert_dir` 只允許一個程序，沒有跨程序鎖定。
- Google Cloud setup 不會設定 IAM 權限，也不會核發公開憑證；憑證由稍後的 ACME 流程向 CA 申請。
- Google SDK 下載使用 HTTPS，程式限制下載及解壓路徑與容量，但沒有比對 checksum，也沒有固定 SDK 版本。
- 新 ACME registration 一律需要 EAB。自訂 directory 必須提供該 CA 的 EAB 值，放入程式讀取的 `GOOGLE_ACME_EAB_KID` 與 `GOOGLE_ACME_EAB_HMAC`；Google setup 只支援 Google production 與 staging directory。
- 尚未提供 CSP enforcement、WebSocket drain API、metrics、supervisor、MFA、跨程序 HA 或共享 limiter。

## 測試對照

| 驗收範圍 | 現有測試 |
| --- | --- |
| Webfile 語法、CLI 覆蓋、預設值及驗證 | [`config_test.go`](../config_test.go)：`TestWebfile`、`TestWebfileErrors`、`TestConfigCLIOverridesFile`、`TestHTTP3ConfigValidation`、`TestExampleWebfile`。 |
| 首頁、健康端點、Basic Auth、速率限制及靜態檔案 | [`server_test.go`](../server_test.go)：`TestDefaultPageAndHealth`、`TestBasicAuth`、`TestRateLimitAndSpoofing`、`TestStaticFiles`、`TestConfigValidation`、`TestActualHTTP`、`TestHTTPServerLifecycle`。 |
| Round-robin、健康檢查、readiness、代理錯誤與並行請求 | [`server_test.go`](../server_test.go)：`TestRoundRobinHealthAndForwarding`、`TestProxyErrorAndReadiness`、`TestConcurrentRequests`。 |
| HTTP-01、HTTP redirect、Host 驗證、ACME 申請、更新與 cache restart | [`tls_test.go`](../tls_test.go)：`TestChallengeAndRedirect`、`TestCertificateCacheAndRenewalWindow`、`TestACMEIssueRenewRestartAndTLS`。ACME 測試使用本機 fixture，不是公開 CA。 |
| HTTPS、HTTP/3、Alt-Svc、認證及憑證輪替 | [`http3_test.go`](../http3_test.go)：`TestHTTP3TLSAuthAndAltSvc`；[`lifecycle_test.go`](../lifecycle_test.go)：`TestRunHTTPSAndHTTP3FromCache`。 |
| WebSocket 與 WSS 雙向訊息 | [`websocket_test.go`](../websocket_test.go)：`TestWebSocketAndWSS`。 |
| Google CLI、專案確認、EAB、SDK 安全解壓及 cache skip | [`bootstrap_test.go`](../bootstrap_test.go)、[`prompt_test.go`](../prompt_test.go)。官方 SDK archive 測試只有設定 `WEB_HTTP_TEST_SDK_ARCHIVE` 時才執行。 |
| Trusted forwarded scheme、canonical redirect、client IP 與 security response headers | [`edge_policy_test.go`](../edge_policy_test.go)：`TestEdgePolicyTrustedRequestMetadata`、`TestEdgePolicyTLSPriorityAndRedirect`、`TestEdgePolicyRedirectUsesCanonicalOriginAndPreservesTarget`、`TestEdgePolicyHealthExceptionAndNoStore`、`TestEdgePolicyAuthoritativeHeadersOnResponses`。 |
| Request body limit 與 413 | [`resource_policy_test.go`](../resource_policy_test.go)：已知／未知長度、limit 0、proxy error mapping。 |
| Safe access log 與 request ID | [`request_log_test.go`](../request_log_test.go)：秘密排除、status、panic、cancellation、flush、hijack。 |

## Cloudflare Tunnel

- Cloudflare edge TLS 可將 HTTPS 或 WSS 流量轉送至 HTTP-only OmniGate origin，再由 OmniGate 轉送到設定的應用程式 upstream。使用 [`cloudflared-example.Webfile`](../config/cloudflared-example.Webfile) 前，請替換 hostname、upstream 和 trusted CIDR。
- OmniGate 只使用設定的 `public_url` 建立 canonical 301。TLS request 視為 HTTPS；HTTP request 只有在 socket peer 符合 `trusted_proxies` 時，才採用單一合法的 `X-Forwarded-Proto`。缺少或無效的 metadata 會讓 HTTP origin 維持 HTTP 判定。請另外驗證 connector metadata；測試 helper 加入 header 不能證明實際 connector 如何傳送。
- `/healthz` 與 `/readyz` 不 redirect。Health response 成功不代表應用程式 upstream 或公網路由正常。
- 隔離 fixture 的 WebSocket echo 只檢查 fixture 與 OmniGate proxy，不能證明其他應用程式的 WS/WSS endpoint 可用。
- Webfile 修改不會熱載入。服務重新啟動可能中斷已升級的 WebSocket 連線。Tunnel restart、Cloudflare edge redirect、cache bypass 和 purge 都需分別授權與驗證。
- [較早的 production 驗證](../reports/production-verification.json) 和[較早的 origin-routing 驗證](../reports/2026-10-09-origin-routing.json)是歷史 artifact 與隔離檢查紀錄。它們不代表 v0.1.0、目前的 tunnel runtime、Cloudflare edge rule、cache 狀態或公網 HTTPS/WSS 已驗證。