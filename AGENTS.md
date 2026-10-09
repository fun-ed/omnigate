# 專案指令

## 入口與範圍

OmniGate 是單站 Go HTTP／HTTPS server，module 為 `github.com/fun-ed/omnigate`，binary 為 `omnigate`。從 [README.md](README.md) 開始，需求與決策以 [plan/2026-10-08-web-server.md](plan/2026-10-08-web-server.md) 及後續計畫為準。行為修改前讀 [docs/specs.md](docs/specs.md)，跨檔流程參考 [docs/architecture.md](docs/architecture.md)。

- `main.go` 管理程序與 listener lifecycle，`config.go` 處理 Webfile／CLI。
- `server.go` 處理 middleware 與檔案，`proxy.go` 管理 upstream／健康檢查。
- `tls.go` 管理 ACME／憑證，`bootstrap.go` 管理 Google setup，`http3.go` 管理 QUIC。
- 使用 Serena 時啟用本專案並讀 `mem:core`，再依其引用讀相關記憶。記憶是導覽，程式與規格是行為依據。

## 修改規則

- 遵守執行環境的共用規則。先讀完整定義、直接影響的 callers 與測試，再做最小修改。
- 維持單一 `main` package 與現有檔案責任，不為假設需求新增 dependency、framework 或 abstraction。
- 使用標準 Go testing 與現有本機 fixture／mock。Go 檔案使用 gofmt，只格式化此次修改的檔案。
- 註解只說明程式無法直接表達的原因。文件使用臺灣繁體中文，命令、log、API 與識別字保留原文。
- 改功能或設定契約時，同步 specs、直接影響的 README／`config/` 範例與計畫完成狀態。工作範圍不符時先回報，不自行擴大。
- 一個工作項目對應一個 branch／PR，合併前需獨立 review 與驗證；計畫更新與變更一起交付。首次 initial commit／release 依使用者明確授權執行。只有使用者要求時才 init、commit 或 push，不加入 AI 作者標記。

## 安全與協定

- Agent 不讀取或保存真實 EAB、帳戶私鑰、憑證私鑰、密碼、OAuth 或 gcloud 登入資料的內容。依使用者授權，server 可將完整 EAB 與帳戶／憑證狀態原子寫入 `cert_dir/state.json`，檔案 `0600`，新目錄 `0700`；這些私密檔案不作為 agent context。
- 變更設定或既有 agent 指令前，先做時間戳備份並確認一致。備份不能進公開 root、報告或版本控制。
- 真實 gcloud 安裝／init、project／API 變更、EAB 申請與 production 操作，先列明目標、範圍、風險、回復與驗證，取得必要授權；不能由預設測試觸發。
- ACME cache 每個目錄只供一個程序使用，不刪除仍可用的 account state 來重試。維護與復原依 [docs/maintenance.md](docs/maintenance.md)。
- 限流預設以 socket peer IP 分桶；只有配置 trusted proxy CIDR 與允許的單一 client-IP header 時，trusted peer 才可使用該 client IP 分桶。維持 edge credential 不轉送 upstream、proxy 不自動重送 request 的契約。認證、headers、ACME／SDK 安全與 lifecycle 修改必須有直接回歸測試。
- WS／WSS 使用 HTTP/1.1 Upgrade，不能把啟用 HTTP/3 當成 extended CONNECT 支援。重啟／shutdown 需考慮已 hijack 的 WS 不會被 HTTP graceful shutdown 排空。
- 排查依 [docs/debug.md](docs/debug.md)。不要以停用 TLS 驗證或刪除 cache 掩蓋問題。
- 固定 Cloudflare Tunnel 的路徑為 Cloudflare edge → HTTP-only Go origin `127.0.0.1:8081` → 既有 Omnigent upstream `127.0.0.1:6767`；不得停止或取代 Omnigent。Go 以固定 `public_url` 建立 301 URL，解析後 scheme 為 HTTP 的應用路徑才 redirect：TLS 優先，HTTP 僅採用 trusted peer 的單一合法 `X-Forwarded-Proto`，缺漏或無效值沿用 HTTP；不得依 request Host 建立 Location 或盲目 redirect。`~/.cloudflared/config.yml` 的磁碟變更不會熱載入；使用者安排 Go 部署後再重啟自己的 tunnel，可能短暫中斷。回復時還原變更前的設定備份並重啟自己的 tunnel。

## 驗證與交付

Go 最低版本與依賴以 `go.mod`／`go.sum` 為準；目前使用 Go 1.27.1。用 mise 執行，不改全域 runtime defaults。

```sh
mise exec go@1.27.1 -- go test -race -count=1 -cover ./...
mise exec go@1.27.1 -- go vet ./...
mise exec go@1.27.1 -- go build -o omnigate .
```

先跑直接覆蓋修改路徑的測試，再執行適用的完整檢查。改 `scripts/` 時另跑：

```sh
mise exec -- python -m unittest discover -s scripts -p 'test_*.py' -v
```

- 修改設定範例後跑 `TestExampleWebfile`；修改文件後檢查相對連結與實際 CLI 選項。純文件改動不必重跑壓測。
- Protocol／lifecycle 改動執行本機 TLS、QUIC 或 WS 測試，不能只用一般 HTTP 成功代替。
- 測試工具用法見 [scripts/README.md](scripts/README.md)，測試證據見 [reports/2026-10-08-load-test.md](reports/2026-10-08-load-test.md)。保留新 raw data、charts 與來源，不覆蓋已發佈結果。
- Short HTTP load、handler microbenchmark 與 RSS 取樣不能證明競品優劣、RAM 峰值、長期穩定性或未測協定容量。
- 完成時報告實際執行的檢查、結果、未驗證範圍與 blocker；不得將 mock 成功寫成真實 Google 簽發成功。
