# OmniGate v0.1.0 首次公開發布

## 授權與範圍

使用者要求 git init、更名 module 與產品、更新 README／gitignore／changelog、git push 及 GitHub Release。公開目標固定為 `fun-ed/omnigate`，初始版本 `v0.1.0`，module `github.com/fun-ed/omnigate`，binary `omnigate`。不改工作目錄、不重啟既有服務、不新增 dependency，也不擅自選擇 license。

## 變更

- [x] 公開檔案審查與私密／工具資料排除。
- [x] module、CLI、default HTML、Basic Auth realm 改名；保留既有環境變數與 Webfile 語法。
- [x] README、設定／維護文件、CHANGELOG 更新。
- [x] 初始化 main 與 origin，使用既定 helper 確認 Git identity。
- [x] Go race／vet、Python tests、範例與品牌回歸通過。
- [x] production binary、build metadata／SHA256、隔離 smoke 通過。
- [x] 明確檔案清單 staging、公開內容再次檢查、commit／push。
- [x] tag／GitHub Release notes、assets 及下載 checksum 驗證。

## 公開邊界

不提交私有 `config/production.Webfile`、`config/google-production.Webfile`、`.certs*`、EAB／account／certificate state、`.env*`、credentials、backups、local binaries、`dist/`、`.serena/`、cache 或 logs。Release 只上傳已驗證的 macOS arm64 binary 與不含本機個資的 build metadata／checksums。

公開測試的 fixture passwords、placeholder emails、runtime-generated keys 不是真實 credentials。公開範例使用 `example.com`、`your-project-id` 與 `YOUR_TUNNEL_ID`；不用真實雲端 project／account。Git commit author 使用個人 identity helper，不在報告抄寫 email。

## 相容性與驗收

品牌改名會改變 default HTML 與 Basic Auth realm，瀏覽器可能重新要求登入。保留 `WEB_HTTP_AUTH_PASSWORD` 等環境變數，避免破壞部署；既有 private Webfile 不需改寫。舊 `web-http` binary 保留但不發布，既有程序不會因新 binary build 而更新。

Go 1.27.1，CGO disabled，trimpath／buildvcs=false／stripped darwin arm64 artifact。驗收 HTTP／trusted 301／Auth／private headers／proxy／WS fixture 和 SIGTERM；不取代真實 Omnigent、公網 tunnel 或 Google ACME 驗收。

保留歷史 benchmark 原數據、web-http 識別與 charts，明確標為歷史證據；沒有新壓測，不聲稱新版本更快或更省 RAM。沒有 license 時，public repo 不等於已授權自由重用。

## 回復

更名前設定／module／agent 指令有已驗證的私有時間戳備份。公開 commit／tag 不 force push、刪除或改寫；發現發布問題時停止發布並另行授權處理。發布不改動正式程序，因此不需要 restart rollback。

## 遠端驗收結果

`main` 已推送至 `fun-ed/omnigate`。`v0.1.0` annotated tag 指向 initial commit `189c176b1f48e42ce922cb3ef5b06fbe439b5d48`，GitHub Release 已公開，notes 與 CHANGELOG 加驗收資訊一致。

Release 提供 `omnigate-darwin-arm64`、`SHA256SUMS`、`build-info.txt`，三份檔案重新下載後全部核對一致。另從公開 `v0.1.0` fresh clone 驗證 private config／工具／dist 不存在、Go tests 通過，並以相同正式 flags 重建出 byte-identical binary。測試及發布證據見 [release verification](../reports/2026-10-10-omnigate-v0.1.0.json)。

Release URL：https://github.com/fun-ed/omnigate/releases/tag/v0.1.0
