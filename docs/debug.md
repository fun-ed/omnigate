# 除錯

本文件依目前的 handler 與啟動流程列出可觀察的錯誤。設定規格見 [specs.md](specs.md)，服務流程見 [architecture.md](architecture.md)。

## 狀態碼與症狀

| 症狀或狀態 | 來源與檢查方式 |
| --- | --- |
| 400 Bad Request | 應用程式路由沒有一般請求的 400 回應。通常是 HTTP parser 拒絕格式錯誤的 request，或 upstream 回傳 400。確認呼叫端使用正確方法、Host、協定及標頭；查看 upstream 自己的日誌。設定錯誤不是 HTTP 400。 |
| 401 Unauthorized | `basic_auth` 已啟用，但帳密缺漏或不符。確認執行程序的密碼環境變數與 `auth-user`，不要把密碼放在命令列。健康端點不經過 Basic Auth；啟用 `private_cache` 時 401 會使用 `private, no-store`。 |
| 413 Content Too Large | request body 超過 `max_body_bytes`。已知超長 `Content-Length` 會在交給 handler 前拒絕；未知長度 body 串流時可能已部分到達後端。確認應用程式上傳政策與設定上限。 |
| 429 Too Many Requests | 每個 limiter key 的 token bucket 用盡，或 limiter 已有 10,000 個 IP 項目且新 IP 被拒絕。回應有 `Retry-After: 1`。沒有可信 proxy 設定時 key 是 socket peer IP；只有 trusted peer 的單一合法 `client_ip_header` 才會分 client bucket。 |
| 502 Bad Gateway | 本次 reverse proxy 連 upstream 失敗。request context 仍有效時會將該 upstream 標成不健康。從服務主機直接檢查 upstream 連線及 health URL，並看 upstream 日誌；服務不會重試同一個應用程式 request。 |
| 503 Service Unavailable | 有 upstream 設定但目前沒有健康 upstream，或 `/readyz` 尚未有健康 upstream。檢查 `health_check` 路徑是否相對於 upstream base path、檢查回應是否為 2xx，以及服務到 upstream 的網路。`/healthz` 仍可能回 200。 |
| 421 Misdirected Request | TLS 模式下的 HTTP listener 收到不符合設定網域的 Host。確認 DNS、Host、HTTP redirect 網域與設定值一致。HTTPS 的錯誤 SNI 會在 TLS handshake 階段失敗，不會由 HTTP handler 回 421。 |
| 404 Not Found | 靜態路徑不存在、隱藏路徑被阻擋、目錄缺少 `index.html`、未配置首頁路徑，或請求的 ACME challenge token 不存在。challenge handler 在沒有正在進行的 token 時回 404 是正常結果。 |
| 405 Method Not Allowed | `/healthz`、`/readyz` 或內建首頁使用了 GET/HEAD 以外的方法；HTTP-01 challenge 只接受 GET，HEAD 也會回 405。 |
| 308 Permanent Redirect | TLS 模式下，HTTP 網域符合但請求不是健康端點或 ACME challenge。檢查 redirect 的 HTTPS 網域與 port。 |
| 301 Moved Permanently | `https_redirect on` 且應用 request 的可信 external scheme 判定為 HTTP。確認 `public_url`、可信 peer CIDR 與 tunnel 提供的單一 `X-Forwarded-Proto`；health path 不適用此 redirect。 |

服務設定解析或驗證失敗會在建立 listener 前讓程序退出，不會透過 HTTP 回應錯誤。`main.go` 會記錄 `server stopped` 及錯誤；沒有設定檢查專用的 dry-run 旗標。

## 安全檢查命令

下列命令用於讀取回應或本機 listener 狀態，不在命令列帶密碼或 EAB。請替換範例網域與 IP。

確認本機 listener：

```sh
lsof -nP -iTCP:80 -sTCP:LISTEN
lsof -nP -iTCP:443 -sTCP:LISTEN
lsof -nP -iUDP:443
```

Linux 可用 `ss -lntup` 檢查 TCP/UDP sockets。這只證明程序在本機監聽，不代表 NAT、防火牆或公網路由可達。

檢查 HTTP 健康、readiness 與 TCP port：

```sh
curl -i --max-time 3 http://127.0.0.1:8080/healthz
curl -i --max-time 3 http://127.0.0.1:8080/readyz
nc -vz example.com 80
nc -vz example.com 443
```

設定 upstream 時，從同一台主機檢查實際 upstream URL 及健康路徑。例如 upstream 是 `http://127.0.0.1:9001/base` 且 health path 為 `/healthz`：

```sh
curl -i --max-time 3 http://127.0.0.1:9001/base/healthz
```

服務的 upstream 健康檢查要求 GET 回 2xx。redirect 或其他狀態不會算健康。

檢查網域、Host、TLS 憑證與 SNI：

```sh
curl -v --resolve example.com:443:203.0.113.10 https://example.com/healthz
openssl s_client -connect 203.0.113.10:443 -servername example.com -brief
```

`--resolve` 會讓測試連到指定 IP，同時保留 URL 的 Host 與 TLS SNI。不要只用 IP 網址測試虛擬網域憑證。不要為了排除憑證問題而長期停用 TLS 驗證。

若 HTTP listener 綁定在本機非 80 port，可測試 Host 與 redirect：

```sh
curl -i -H 'Host: example.com' http://127.0.0.1:8080/path
curl -i http://127.0.0.1:8080/healthz
```

啟用 TLS 時，第二條健康路徑不驗證 Host，也不會 redirect；一般路徑需要正確 Host。

## Proxy headers

`edge_policy.go` 只對 `trusted_proxies` CIDR 內的 socket peer 採用單一合法 `X-Forwarded-Proto` 或配置的 client IP header；沒有可信 metadata 時仍使用 origin scheme 與 peer IP。TLS 連線本身優先於 forwarded scheme。不要以未驗證的 client `X-Forwarded-For` chain 計算 limiter bucket。`proxy.go` 會用 `httputil.ProxyRequest.SetXForwarded` 設定 upstream forwarding headers，並移除 `Forwarded`；Basic Auth 通過後會先移除 `Authorization`。


## ACME 與 Google setup

HTTP-01 驗證需要公用 TCP 80 轉送到 `-http` listener，DNS 必須指向該 listener 對外可達的主機。檢查：

1. 服務帳號能綁定設定的 HTTP 位址與 port。
2. DNS 的 A/AAAA 記錄及 NAT、防火牆允許公用 TCP 80。
3. ACME directory、domain、email 與 cache 身分一致。
4. CA 要求驗證時，TCP 80 上的 HTTP handler 正在運作。
5. 憑證到期日與目前時間正確，系統時鐘沒有偏差。

HTTP-01 path 只有 CA 正在驗證且 token 仍在記憶體 map 中時才會回 key authorization。對不存在的 token 執行 `curl` 取得 404，不能用來判定 ACME listener 有問題。也不要在一般日誌或問題回報中貼出 challenge authorization、帳戶私鑰、憑證私鑰或 EAB。

Google setup 是互動流程。若專案清單或 Public CA API 步驟失敗，先確認目前 gcloud 帳號及可列出的專案：

```sh
gcloud auth list
gcloud projects list --format='value(projectId)'
```

確認選用專案已啟用 `publicca.googleapis.com`，且操作者有權限啟用 API 及建立 Public CA external account key。程式不會自行增加 IAM 權限。手動安裝 gcloud 時也要確認相容 Python 3 已存在。不要為了診斷而盲目重跑 setup、建立多組 EAB 或將 gcloud 輸出貼到工單；EAB 是敏感憑證。

新 ACME registration 需要一組完整 EAB，優先使用 `GOOGLE_ACME_EAB_KID`／`GOOGLE_ACME_EAB_HMAC`，兩者皆未設定時使用 private cache 中的 pair；都沒有且已啟用 Google setup 時才取得新 EAB。Partial env pair 會失敗，不混合其他來源。完整 pair 在註冊前與 account key 保存至 `state.json`，不要輸出檔案內容。自訂 ACME directory 使用該 CA 的 EAB，Google setup 只支援 Google production 或 staging。已使用或過期的 EAB 不保證能再註冊，先透過 saved account key 解析既有 registration；續期不需要 EAB。若初始更新失敗但 cache 有仍有效憑證，服務會以 cache 啟動並每小時重試。先修復網路、DNS 或 CA 設定並保留 cache，不要刪除 account state。

## HTTP/3 與 WebSocket

HTTP/3 需要 HTTPS 憑證、可到達的 UDP port，以及支援 HTTP/3 的 curl。先確認 curl build feature：

```sh
curl -V
curl --http3-only --resolve example.com:443:203.0.113.10 https://example.com/healthz
```

只有 curl 顯示支援 HTTP/3 時，第二條命令才可用；否則應使用專案的 Go 測試 `TestHTTP3TLSAuthAndAltSvc` 或 `TestRunHTTPSAndHTTP3FromCache`。TCP 443 可達不代表 UDP 443 可達。確認 HTTP/3 旗標、UDP 防火牆/NAT、憑證與 SNI。

WebSocket 使用 HTTP/1.1 Upgrade。下列 curl 命令可檢查 handshake 是否回 101：

```sh
curl --http1.1 -i -N \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  https://example.com/socket
```

curl 顯示 101 只代表 handshake 成功，不會驗證完整雙向 WebSocket frame。完整檢查需用會交換訊息的 WebSocket client，或執行 `TestWebSocketAndWSS`。WebSocket 的 Basic Auth 仍在 edge 驗證，密碼若需手動輸入，使用會提示輸入密碼的互動 client，不要用 `-u user:password`。

## 日誌與可觀察性

啟用 `access_log` 後，每筆 completion log 只包含自產 request ID、method、status、duration、`origin_scheme` 與 completion 狀態。`origin_scheme` 僅反映 Go origin transport（TLS／明文），不代表 Cloudflare 到 client 的 scheme 或 trusted forwarded scheme。Log 不含 path、query、Authorization、Cookie、body 或 username，也不是 metrics endpoint。保留完整錯誤類型和必要 status 供診斷，不要將憑證或密碼貼入一般日誌。

## Cloudflare Tunnel 排查

- Origin `address already in use`：檢查設定的 listener 位址。若已被占用，不要停止不明程序；檢查 upstream health endpoint 及連線設定。
- HTTP redirect loop：網域模式 308 與 HTTP-only origin 的 `https_redirect` 301 是不同機制。檢查固定 `public_url`、可信 peer CIDR，以及 connector 提供的單一 external scheme。只有可信 peer 的合法 `X-Forwarded-Proto` 可改變 origin HTTP 判定；不可信或缺漏值會回到 HTTP。Helper 加入的 scheme header 只模擬 trusted metadata，不能證明 Cloudflare 實際提供該 header。
- 429 或多位訪客被合併計數：檢查 `trusted_proxies` 是否只包含實際 origin peer，以及 `client_ip_header` 是否為允許的單一 IP header。不要直接信任 `X-Forwarded-For`。
- Health 回 200 但 application marker 不符：可能流量仍到其他 connector 或舊服務。Health 成功不足以證明路由身分；fixture marker 只證明該次 OmniGate proxy 到 fixture。其他應用程式的 WS/WSS endpoint 需另外驗收。
- Cloudflare cache HIT 沒有反映 origin policy：`private_cache` 只影響抵達 OmniGate 的 response，不能使已 cache 的 edge object 失效。檢查 hostname/path 範圍明確的 cache bypass；需要時由有權限的管理者執行 scoped purge，流程見 [Cloudflare 說明](cloudflare.md)。

Tunnel ingress CLI validate 只證明磁碟設定可解析，不證明 connector 已載入該設定，也不代表 Cloudflare edge 或公網已驗收。設定變更、tunnel restart、edge redirect、cache bypass 與 purge 需分別安排和授權。