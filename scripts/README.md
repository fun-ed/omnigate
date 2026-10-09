# 測試工具

這些工具只使用 Python 標準函式庫，不加入 server runtime dependency。本次使用 Python 3.14.8；一般執行需要 Python 3.10 以上。Go benchmark 使用專案要求的 Go 版本。

## HTTP closed-loop 負載測試

`load_test.py` 以 threads 執行 HTTP/1.1 GET，每個 worker 使用一條 keep-alive connection。支援 HTTP／HTTPS；HTTPS 預設驗證憑證，可指定 `--cafile`。它不支援 HTTP/2／HTTP/3／WS，也不是 open-loop generator。

預設只允許 loopback，拒絕 URL credentials、query 與 fragment。遠端測試需要 `--allow-remote`，且必須先取得目標管理者同意。請只測自己的服務。Body 上限為 1 MiB；本工具不適合下載大檔案測試。

### 1. 啟動本機測試 server

在專案 root 編譯，然後背景啟動，記下 PID。

```sh
mise exec go@1.27.1 -- go build -o omnigate .
./omnigate -http 127.0.0.1:8080 -rate 0 &
server_pid=$!
printf 'server PID: %s\n' "$server_pid"
curl --fail --max-time 3 http://127.0.0.1:8080/healthz
```

只在本機測量 throughput 時停用限流。不要把 `-rate 0` 當成公網部署建議。若 port 無法 bind，改用另一個可用 port，並同步修改測試 URL。

### 2. 保存新的測試資料

同一個 shell 保留 `server_pid`。Output 檔案必須不存在，且目錄由你掌握。

```sh
mise exec -- python scripts/load_test.py \
  --url http://127.0.0.1:8080/ \
  --concurrency 1,10,40,100 --duration 10 \
  --server-pid "$server_pid" \
  --output reports/local-http-load.json
```

工具保存時間、OS／architecture／logical CPUs／Python、狀態與錯誤、成功請求 latency percentile、server PID 的 RSS samples。沒有 `--server-pid` 時不會量測 RSS。`ps` 無法取樣時也不會假造記憶體數值。

預設 timeout 5 秒，成功狀態固定為 200。以 `--help` 查看完整選項。非 200 status 或 exception 記為錯誤，測試結束 exit code 1；資料仍寫出供診斷。Percentile 只包含成功請求。

### 3. Microbenchmark 與 charts

先把以下命令的 stdout 保存成新的文字檔，例如 `reports/local-handler-bench.txt`。不要覆蓋已發佈的原始測試資料。

```sh
mise exec go@1.27.1 -- go test -run '^$' -bench . -benchmem -benchtime=1s -count=1 ./...
```

將 JSON 與 benchmark 輸入圖表工具。沒有 benchmark 文字也可省略 `--bench`。

```sh
mise exec -- python scripts/render_charts.py reports/local-http-load.json \
  --bench reports/local-handler-bench.txt \
  --output-dir reports/local-charts
```

產生 throughput、latency、memory SVG，有 benchmark 時另產生 handler chart。工具拒絕覆蓋圖表；另一組結果使用新目錄或 `--prefix`。`--prefix` 不接受路徑分隔符。

SVG 可直接用瀏覽器或 Markdown viewer 開啟。Memory 圖若沒有 RSS 資料，不會畫出假的曲線。最後將測試條件、原始資料、build provenance、charts、限制與結果一起寫入報告。

### 4. 結束 server

```sh
kill -TERM "$server_pid"
wait "$server_pid"
```

只停止自己剛啟動的程序。`wait` 的結果是 shutdown 驗證的一部分；不要用模糊名稱的 `pkill` 停止其他服務。

## 工具驗證

```sh
mise exec -- python -m unittest discover -s scripts -p 'test_*.py' -v
```

測試涵蓋 URL 安全限制、percentile、本機 HTTP 實際請求、SVG XML 與字元 escaping。這不等於 load generator 校準，也不驗證 server 的 production 容量。

目前結果與 charts 見 [2026-10-08-load-test.md](../reports/2026-10-08-load-test.md)。

## Cloudflare Tunnel 的 HTTP／WS／WSS 驗收

先在自己管理的環境中確認 OmniGate origin 可用。使用隔離 upstream 驗證 proxy 與 WebSocket，不要將 fixture 當成正式應用。Cloudflare 範本需先替換 hostname、upstream 與 trusted CIDR。設定不會熱載入，Tunnel 或 Cloudflare 設定也不會由此工具修改。

首次使用時，從 repository root 將公開範本複製到私密設定檔。若目標已存在，請勿覆寫；檢查並使用現有檔案。複製後先編輯 `config/production.Webfile`，設定自己管理的 hostname、upstream 與可信 CIDR。

```sh
if [ -e config/production.Webfile ]; then
  printf 'config/production.Webfile already exists; refusing to overwrite\n' >&2
  exit 1
fi
cp config/cloudflared-example.Webfile config/production.Webfile
chmod 600 config/production.Webfile
```

1. 在第一個終端啟動隔離 upstream。每次測試都使用新的 marker，避免將舊回應誤認為本次測試結果。

   ```sh
   mise exec -- python scripts/tunnel_acceptance.py fixture \
     --marker omnigate-acceptance-unique-id
   ```

   第一行會輸出暫時的 loopback URL。保持 fixture 執行，記下 URL 中的 port，下一步用它取代 `FIXTURE_PORT`。

2. 在第二個終端安全讀入 Basic Auth 密碼，再啟動 OmniGate。此命令的 `-upstreams` 會把應用路徑導向 fixture，不會導向原本的應用 upstream。

   ```sh
   printf 'Basic Auth password: '
   read -r -s WEB_HTTP_AUTH_PASSWORD
   printf '\n'
   export WEB_HTTP_AUTH_PASSWORD
   ./dist/omnigate-darwin-arm64 -config config/production.Webfile \
     -upstreams http://127.0.0.1:FIXTURE_PORT
   ```

   只在明確接受測試流量經過該 fixture 時，才繼續公網驗收。不要把這個 OmniGate 執行個體用於必須送到正式應用 upstream 的流量。

3. 只有在測試管理者授權且接受短暫中斷時，才重啟自己管理的既有 connector，讓它載入更新後設定。不要另開第二個 connector。Connector 命令、設定路徑與身分由該環境的管理者提供；不得將 tunnel ID 或 credentials file 路徑寫進公開文件。

4. 對自己管理且已設定的 public hostname 執行 probe。將 `PUBLIC_URL` 設為該 hostname 的 HTTPS URL，並使用尚不存在的輸出路徑。工具不應用於未經授權的主機。

   ```sh
   : "${PUBLIC_URL:?set PUBLIC_URL to a hostname you control}"
   mise exec -- python scripts/tunnel_acceptance.py probe \
     --origin http://127.0.0.1:8081 --public "$PUBLIC_URL" \
     --marker omnigate-acceptance-unique-id --user admin \
     --password-env WEB_HTTP_AUTH_PASSWORD \
     --origin-external-scheme https \
     --output reports/local-tunnel-acceptance.json
   ```

`--origin-external-scheme https` 只在已驗證的 loopback HTTP origin checks 中加入 `X-Forwarded-Proto: https`，涵蓋 HTTP 與 WebSocket。此旗標不影響 public request，也不略過 Basic Auth。它只模擬可信 metadata，不能證明 Cloudflare 或 connector 實際提供或覆寫該 header。公開 probe 仍會執行 HTTPS/WSS authentication checks。

Probe 檢查兩端的 health、readiness、未登入 401、登入後 marker 與 WebSocket echo。Fixture 的 `/socket` echo 只驗證 fixture／OmniGate proxy，不能證明其他應用程式的 WS/WSS endpoint。未執行的項目必須明列；每次測試使用新的報告路徑，不覆寫既有結果。

結束後只停止本次自行啟動的 fixture 與 OmniGate 程序。不要停止其他服務或 connector。清除 shell 中的 `WEB_HTTP_AUTH_PASSWORD`。Fixture 僅綁定 loopback，拒絕收到 Authorization，因此 marker／echo 也能檢查 OmniGate 沒有將 Basic Auth 憑證轉送 upstream。
