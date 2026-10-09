# Improvement 追蹤

## 原則與現況

目前部署為 Cloudflare → cloudflared → Go `127.0.0.1:8081` → Omnigent `127.0.0.1:6767`。本次使用者要求記錄改善項目、完成後打勾，並先實作可在本專案完成的功能。勾選只代表該項列出的驗收已完成，不把原始碼完成寫成公網已部署。

本機與公網的 Basic Auth challenge 已驗證。2026-10-09 的唯讀檢查另發現：public HTTP `/` 回 401 而非 HTTPS redirect；一個 hashed JS asset 在 Go 未認證回 401，Cloudflare 卻以 cache HIT 回 200。這只證明靜態檔案的 cache／認證邊界不一致，不代表私人 API 資料已洩漏。

## 第一批，專案內實作

- [x] 可設定 HTTPS 301 redirect，使用固定 public URL，保留 path／query，避免 Host open redirect。
- [x] 可信 proxy CIDR、經驗證的 client IP 與 external scheme；未受信任的 forwarded headers 不生效。
- [x] 正確傳遞 upstream client IP／HTTPS scheme，維持 edge Authorization 不轉送的契約。
- [x] 私人網站 cache policy，覆寫 upstream 的 public cache header；不宣稱能清除既有 edge／Service Worker cache。
- [x] 可設定 HSTS、frame protection 與 Referrer-Policy；HSTS 僅在已判定 HTTPS 的回應生效。
- [x] 可設定串流 request body byte cap，固定長度過大預先回 413，未知長度讀取超限回 413，不把 client input error 當 backend unhealthy。
- [x] 可設定 request log 與自產 request ID，不記錄帳密、cookie、query、原始 path、body 或私人資料。
- [x] 更新 Webfile／CLI、production profile、specs、README、維護與 debug 文件。
- [x] Go race／vet、Python 工具回歸、獨立 review、production build／checksum 與隔離 smoke 通過。

本批開發契約見 [2026-10-09-hardening.md](2026-10-09-hardening.md)。新欄位預設關閉，以保留原設定相容性；production profile 明確啟用適合私人入口的項目。上傳 byte cap 先保持 0，待確認 Omnigent 合法上傳需求後才設定實際值。

完成證據：[2026-10-09-hardening.json](../reports/2026-10-09-hardening.json)。Go statement coverage 80.3%，Python 12 tests；WS 101 headers／request-ID、frame round trip、103／trailer 已直接回歸。磁碟 artifact 已更新，執行中的 Go／tunnel 未重啟；正式部署與公網操作仍保留以下未完成核取項目。

## 部署與 Cloudflare，需另外完成

- [ ] 使用者將容易猜測的測試密碼換成強密碼；不把密碼寫進 config、文件、plist 或 command line。
- [ ] 確認整站私人或公開 static 的產品政策。目前以私人入口為保守設定，不新增 public path 例外。
- [ ] Cloudflare edge 強制 HTTPS。全 zone 的 Always Use HTTPS 會影響其他 hostname；只保護 `omni.curl.rs` 時使用 hostname-scoped Redirect Rule。
- [ ] 對私人 hostname／路徑設定 cache bypass，檢查 rule order 與是否存在 override origin cache headers 的規則。
- [ ] 經授權處理先前已快取的私人 objects，再測未認證請求不會從 edge 取得它們；不擅自 purge。
- [ ] 使用者部署新 binary 並重啟自己的 Go 服務。部署會中斷連線，須自行安排時機；agent 不停止既有 Go／Omnigent／tunnel。
- [ ] 公網 HTTP 301、HTTPS 不重導、401 challenge、登入後 proxy、cache 與 headers 實際驗收。
- [ ] 如仍要求固定 HTTP2 tunnel，啟動時明確指定 `--protocol http2`；QUIC tunnel transport 不能當 Go HTTP3 驗收。
- [ ] Cloudflare Access／MFA／SSO 與 WAF policy，需帳號權限及產品決策。

## 後續功能與維運

- [ ] 可設定 active HTTP／WS connection admission limit，含 per-client 與全域上限。
- [ ] WS 連線追蹤、停止新 upgrade、bounded drain 與重連測試；frame size／heartbeat／Origin policy 與 Omnigent 協調。
- [ ] 確認 Omnigent 的實際 WSS endpoint；fixture echo 不取代應用驗收。
- [ ] 確認 SSE／長工作串流及慢速 upload 需求，提供合適的可設定 timeout，不全域取消保護。
- [ ] CSP Report-Only 與前端／Cloudflare scripts／WSS 相容性驗證，再決定 enforcement。
- [ ] 檢查 Omnigent 的 API auth、Authorization Bearer 與外層身份分工、CSRF、cookie、權限隔離與資料備份。
- [ ] macOS launchd 或目標主機 service manager、安全取得秘密、開機啟動、restart backoff 與 log rotation；不在 plist 保存密碼。
- [ ] 受限 metrics、backend health／request／WS 指標、外部探測及告警，限制 labels 基數。
- [ ] CI：race tests、vet、govulncheck、版本化發布與 rollback；目前不是 Git repo，不擅自 init。
- [ ] 純設定檢查指令，無 listener、Google API 或其他外部副作用。
- [ ] 設定 reload／部署排空策略，先處理 WS 生命周期再承諾 zero downtime。
- [ ] 依需求新增獨立主機 failover；先確認 Omnigent session／任務／儲存一致性，不把同機多程序當 HA。
- [ ] Production workload 的 RSS、延遲、429／5xx、長連線與恢復測試；保留舊 benchmark 的原測量範圍。
- [ ] 獨立 Google TLS profile 的真實簽發、續期告警、加密備份／還原與 SDK 發佈物完整性驗證；本次 tunnel 不申請 Google 憑證。

## Cloudflare 操作來源

- [Always Use HTTPS](https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/)：SSL/TLS → Edge Certificates → Always Use HTTPS；影響 zone 中的 hosts。
- [Single redirects](https://developers.cloudflare.com/rules/url-forwarding/single-redirects/)：可限定 hostname。
- [Cache Rules settings](https://developers.cloudflare.com/cache/how-to/cache-rules/settings/)：Cache eligibility 選 Bypass cache；rule override 可能忽略 origin header。
