# 維護

本文件說明 OmniGate v0.1.0 的建置、測試、啟動與狀態維護方式。服務規格見 [specs.md](specs.md)，架構與狀態格式見 [architecture.md](architecture.md)。

## 建置、測試與啟動

專案使用 Go 1.27.1。直接依賴含 lego/v4 4.35.2、quic-go 0.63.0 及 x/time 0.16.0；其餘模組版本列在 [`go.mod`](../go.mod) 與 [`go.sum`](../go.sum)。安裝相容的 Go 版本後，可執行：

```sh
mise exec go@1.27.1 -- go version
mise exec go@1.27.1 -- go mod download
mise exec go@1.27.1 -- go test -race ./...
mise exec go@1.27.1 -- go vet ./...
mise exec go@1.27.1 -- go build -o omnigate .
```

本機只測 HTTP 且不連雲端時，可直接執行：

```sh
./omnigate -http 127.0.0.1:8080
```

正式啟動前，先檢查 Webfile 及所需環境變數，再由服務管理器使用管理者提供的設定路徑啟動：

```sh
omnigate -config "$OMNIGATE_CONFIG"
```

請先設定 `OMNIGATE_CONFIG` 為受控的 Webfile 路徑。`-config` 本身不會避免外部副作用。若設定含 `google_setup on`，或使用 `-setup-google`，啟動會進入互動流程，可能呼叫 gcloud、啟用 Public CA API 並取得 EAB。不要直接執行未修改的 `Webfile.example`，其中含有 Google setup。程式沒有只檢查設定但不啟動的旗標；解析或驗證失敗會在 listener 開啟前退出。

取得 v0.1.0 可執行檔的 Go 安裝方式：

```sh
go install github.com/fun-ed/omnigate@v0.1.0
```

修改 Webfile、環境變數或二進位檔後，手動重啟服務才能套用設定。程式沒有 hot reload。關閉時會對 HTTP、HTTPS、HTTP/3 執行 shutdown，但 Go HTTP shutdown 不會等待已 hijack 的 WebSocket 連線。若不能中斷 WebSocket，部署前需由上游流量管理層先停止新連線並安排連線排空；OmniGate 本身沒有 drain API。

使用 Cloudflare 範本時，先將 `public_url`、upstream 與 trusted CIDR 改成實際環境值。確認 tunnel peer 後才信任 forwarded scheme 或 `CF-Connecting-IP`。應用 upload policy 確認前，維持 body cap 關閉。Go 設定不會變更 Cloudflare edge redirect 或既有 cache object；操作方式見 [Cloudflare 說明](cloudflare.md)。

## 網路與 Google Cloud 權限

- 將公用 TCP 80 轉送到 `-http` listener。HTTP-01 需要 CA 從公網讀取 challenge，即使 HTTP listener 使用非標準 port，外部仍須轉送 port 80。
- 將 HTTPS TCP port 轉送到 `-https`，預設為 443。
- 啟用 `-http3` 時，另將設定的 UDP port 轉送到 listener。它與 HTTPS TCP 可使用相同數字的 port，但仍是不同協定。
- DNS 必須將設定網域指向此服務可從公網到達的位址。HTTP Host 與 TLS SNI 也必須使用設定網域。
- 首次 Google setup 的 gcloud 身分需要能列出可用 project、在確認的 project 啟用 `publicca.googleapis.com`，並建立 Public CA external account key。實際權限由 Google Cloud project policy 決定；程式不會授予 IAM 角色或修改 IAM policy。
- 若服務帳戶或操作者沒有上述權限，請由有權限的人員先完成必要設定，或使用既有的 Google ACME EAB 環境變數。不要把 EAB 寫入 Webfile、命令列或版本控制。

v0.1.0 未驗證真實 Google login、project 或 API 變更、EAB 建立或憑證簽發。以 mock 驗證的程式行為不能證明真實 Google 操作成功。

## ACME cache 備份與還原

`cert_dir/state.json` 保存帳戶私鑰、憑證私鑰、憑證、ACME registration，以及新註冊使用的完整 EAB。EAB 欄位為 `eab_kid` 與 `eab_hmac`；舊 state 缺少這些欄位仍可讀。將整個狀態當成機密資料處理：備份位置需加密並限制讀取者，不要把內容貼到終端記錄、工單或聊天中。程式以 `0600` 寫狀態檔，建立新狀態目錄時使用 `0700`；既有目錄不會自動 chmod，部署前需確認目錄由服務帳號掌握且不在公開 root。

備份前先確認目標儲存位置已受存取控制，並確保不覆蓋既有備份。先設定兩個變數，並為每次備份選新的空目錄：

```sh
: "${CERT_DIR:?set CERT_DIR to the private ACME state directory}"
: "${BACKUP_DIR:?set BACKUP_DIR to a new private backup directory}"
umask 077
mkdir -m 700 "$BACKUP_DIR"
cp -p "$CERT_DIR/state.json" "$BACKUP_DIR/state.json"
```

完成後將備份移入加密且有限權限的備份系統。不要輸出狀態檔內容。

還原時先停止服務，避免同一 cache 同時被兩個程序使用。將備份還原到新的空目錄，並把該目錄設為只有服務帳號可讀取；狀態檔權限應為 `0600`。設定 `-cert-dir` 指向還原目錄，並維持原有的 ACME domain、email 與 directory。然後只啟動一個服務程序。程式會拒絕身分不符的 cache；不要藉由刪除或改寫有效的 `state.json` 來繞過檢查。若現有 cache 尚未恢復或身分不確定，保留原檔並在另一個新目錄還原備份。

```sh
: "${BACKUP_DIR:?set BACKUP_DIR to the private backup directory}"
: "${RESTORE_DIR:?set RESTORE_DIR to a new empty private directory}"
mkdir -m 700 "$RESTORE_DIR"
cp -p "$BACKUP_DIR/state.json" "$RESTORE_DIR/state.json"
chmod 600 "$RESTORE_DIR/state.json"
```

ACME directory、網域或信箱不同時，不得重用同一份 cache。若需並行測試另一組身分，使用另一個 `cert_dir`。不要同時啟動兩個共用相同 `cert_dir` 的程序，程式沒有跨程序鎖定。

## 憑證更新與復原

服務在憑證有效期最後三分之一開始更新，並每小時檢查一次。續期失敗時會保留仍有效的快取憑證並繼續提供 HTTPS，之後每小時重試。這不代表服務能在憑證過期後繼續成功完成 TLS handshake；到期後 `GetCertificate` 會拒絕提供憑證，應在到期前處理 DNS、TCP 80、CA 或 EAB 問題。

首次申請失敗時，若 `cert_dir` 沒有可用憑證，服務會退出而不開啟 HTTPS listener。若有效 cache 存在，即使啟動時更新失敗，服務會使用該憑證啟動並在背景重試。復原時先保留 cache，檢查網域解析、防火牆與 CA 設定，再重啟服務；不要刪除帳戶資料來重試註冊。

保存 EAB 只供尚未完成註冊的 retry 使用，它是短效且單次使用，不能替代 account key。已完成註冊後，重啟及續期不依賴 EAB 或 gcloud。若 EAB 已過期且 CA 確認帳戶不存在，提供新的完整 EAB 環境變數組合；不要只改一個值，也不要刪除 account key。

## 升級與設定變更

1. 取得要部署的 OmniGate 版本及對應設定變更，確認 Go 版本與 `go.mod` 相容。
2. 執行上方測試、vet 與 build 命令。若升級 Go 模組，檢查 `go.mod` 和 `go.sum` 的變更。
3. 先備份設定及 ACME cache。不要備份或記錄密碼、EAB 或 `state.json` 明文內容到一般工作目錄。
4. 確認新設定使用相同的 ACME directory、網域及信箱，並確認 Basic Auth／EAB 環境變數。若使用 Cloudflare 範本，另確認 trusted CIDR 對應實際 origin peer，且 connector 的 forwarded scheme／client IP metadata 有獨立驗證；未確認時不要信任 header。
5. 停止舊程序，再部署新二進位檔及設定，最後啟動一個程序。若新程序無法啟動，還原先前的二進位檔或設定，保留 cache 不動。
6. 從服務日誌確認啟動、listener、ACME 與憑證狀態，再以外部連線檢查 HTTP、HTTPS 及選用的 HTTP/3。

Google Cloud CLI 安裝流程下載官方 SDK archive 並限制檔案大小與解壓路徑，但目前不固定 SDK 版本，也不驗證 checksum。此安裝路徑不會修改 shell PATH 或 profile，並要求系統已安裝相容 Python 3。依組織供應鏈政策，應在批准該安裝路徑前另行確認 SDK 發佈物完整性。
