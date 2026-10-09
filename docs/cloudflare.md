# Cloudflare Tunnel 與 HTTPS redirect

本文件說明如何搭配 HTTP-only OmniGate origin 使用 Cloudflare Tunnel。設定檔與 binary 的修改不會影響已執行的程序；部署需要管理者安排更新、檢查設定並重啟。本文沒有執行 Cloudflare 設定變更，也沒有驗證任何公網行為。

設定範圍與待改善項目見 [production guide](production.md) 和 [實作規格](specs.md)。

## Go origin 的 redirect 與信任邊界

OmniGate 可在 HTTP origin 上回應 301；`public_url` 是唯一 redirect target，不會從 request `Host` 建立 URL。`https_redirect on` 只 redirect 解析後仍是 HTTP 的應用程式路徑；`/healthz` 與 `/readyz` 不 redirect。301 保留 escaped path 與 query。TLS 連線本身優先判定為 HTTPS；HTTP transport 只有在 socket peer 位於 `trusted_proxies` CIDR 時才採用單一合法的 `X-Forwarded-Proto: http` 或 `https`。重複值、逗號串列與其他值會被忽略；沒有有效 forwarded scheme 時，HTTP origin 仍判定為 HTTP，因此啟用 redirect 時會回 301。

可信 peer CIDR 必須對應實際連到 OmniGate listener 的 tunnel peer，範圍應盡可能小。沒有可信 peer 時，OmniGate 忽略 forwarded metadata。若 Cloudflare 或 `cloudflared` 無法保證只向 origin 提供正確的 external scheme，就不要啟用 `https_redirect`，也不要把未驗證的 client IP header 用於 limiter。

以下範例使用 `example.com` 與 loopback upstream。請在自己的部署中替換 hostname、upstream 和 peer CIDR，並驗證 tunnel 實際連線來源：

```text
:8081 {
    http 127.0.0.1:8081
    public_url https://example.com
    https_redirect on
    trusted_proxies 127.0.0.1/32 ::1/128
    client_ip_header CF-Connecting-IP
    private_cache on
    hsts_max_age 86400
    frame_options SAMEORIGIN
    referrer_policy strict-origin-when-cross-origin
    max_body_bytes 0
    access_log on
    rate_limit 10 20
    basic_auth admin env:WEB_HTTP_AUTH_PASSWORD
    reverse_proxy http://127.0.0.1:9001
    health_check /healthz 10s
}
```

`client_ip_header` 只接受 `CF-Connecting-IP` 或 `X-Real-IP`，且需要 `trusted_proxies`；OmniGate 只採用一個有效 IP，不展開 `X-Forwarded-For` chain。若使用 CLI，對應旗標為 `-public-url`、`-https-redirect`、`-trusted-proxies`、`-client-ip-header`、`-private-cache`、`-hsts-max-age`、`-frame-options`、`-referrer-policy`、`-max-body-bytes` 與 `-access-log`。

`public_url` 必須是固定 HTTPS origin，不接受 userinfo、query、fragment 或非根路徑；`https_redirect` 需要設定 `public_url`。`private_cache` 將應用程式回應設為 `private, no-store`，並移除 origin 的 shared-cache 時效標頭。它無法刪除 Cloudflare 已保存的 cache object。`hsts_max_age` 預設為 0，只有判定為 HTTPS 的 response 才會加上 HSTS。Health response 一律 `private, no-store`。開啟 private cache 時，401 也會使用 `private, no-store`。

`max_body_bytes 0` 表示不限制 request body。應先確認應用程式的 upload policy，再設定正值。未知長度 body 以串流方式限制，超限時可能已有部分內容送到 handler 或 upstream。

`access_log on` 只記錄自產 request ID、method、status、duration、`origin_scheme` 與 completion 狀態。`origin_scheme` 只表示 OmniGate 收到請求時的 transport（TLS 為 `https`，明文為 `http`），不表示 Cloudflare client-to-edge scheme 或 forwarded scheme。Log 不記錄 path、query、Authorization、Cookie、request body 或 username。這項設定不會提供 metrics endpoint。

## Cloudflare edge 的 HTTPS 與快取

Cloudflare 的 **Always Use HTTPS** 會影響該 zone 的所有 hostname。只有在接受 zone-wide 影響時才啟用。若只需為一個 hostname 強制 HTTPS，建立 hostname-scoped Single Redirect Rule，條件只匹配該 hostname 的 HTTP request，目標固定為相應的 `https://` URL，保留原 path 與 query，狀態碼使用 301。不要將規則套用至其他 hostname。

Cloudflare edge redirect 與 OmniGate origin redirect 是不同控制：edge rule 在 request 到 origin 前轉址；origin 的 301 只處理已到達 OmniGate 的 request。OmniGate 無法讓既有 Cloudflare cache HIT 重新到 origin，因此 `private_cache` 或 `Cache-Control: no-store` 不能替代 edge cache bypass 或 purge。

若應用程式路徑不應由 Cloudflare cache 提供，建立作用範圍明確的 Cache Rule，將符合的 hostname／path 設為 **Bypass cache**。Rule 的條件需符合實際應用路徑，避免意外將同 zone 的其他 hostname 或公開靜態內容一起 bypass。清除既有物件時，由有權限的 zone 管理者執行範圍最小的 URL 或 hostname purge。Purge 與 dashboard rule 變更都是 Cloudflare 操作，需另行授權。

Cloudflare 官方參考：

- [Always Use HTTPS](https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/)
- [Cache Rules settings](https://developers.cloudflare.com/cache/how-to/cache-rules/settings/)

## 驗收與 rollout

先以隔離 upstream 與 loopback OmniGate listener 驗收，再安排 production restart 和 Cloudflare edge 操作。Python acceptance helper 的 `--origin-external-scheme https` 只把 `X-Forwarded-Proto: https` 加到已驗證的 loopback HTTP origin HTTP／WebSocket checks。此選項不影響 public probe，也不跳過 Basic Auth；它模擬可信 forwarded metadata，不是 Cloudflare 有送出或覆寫該 header 的獨立證據。

實際的 origin peer CIDR、Cloudflare／connector forwarded header、redirect location、cache rule 命中與 purge 結果都須分開驗收。只修改本機設定、fixture probe 通過或 origin 回應成功，都不代表 Tunnel 已重啟、Cloudflare rule 已部署，或公網 redirect／cache 行為已驗證。Production 操作順序見 [production.md](production.md)，設定細節見 [config/README.md](../config/README.md)。

CSP enforcement、WebSocket drain、metrics、supervisor、MFA 與 HA 尚未實作，也不屬於 v0.1.0 的功能。
