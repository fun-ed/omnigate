package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	googleStagingACME        = "https://dv.acme-v02.test-api.pki.goog/directory"
	googleStagingAPIEndpoint = "https://preprod-publicca.googleapis.com/"
	googleCLIBaseURL         = "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/"
	googleCLIArchiveMax      = int64(512 << 20)
	googleCLIExpandedMax     = int64(1 << 30)
	googleCLIEntryMax        = 100000
)

type googleCommandRunner func(context.Context, string, []string, []string, io.Reader, io.Writer, io.Writer) error

type googleBootstrapDeps struct {
	run      googleCommandRunner
	lookPath func(string) (string, error)
	homeDir  func() (string, error)
	http     *http.Client
	goos     string
	goarch   string
}

var googleDeps = googleBootstrapDeps{
	run:      runGoogleCommand,
	lookPath: exec.LookPath,
	homeDir:  os.UserHomeDir,
	http:     newGoogleHTTPClient(),
	goos:     runtime.GOOS,
	goarch:   runtime.GOARCH,
}

func runGoogleCommand(ctx context.Context, executable string, args []string, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = env
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func newGoogleHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Hostname(), "dl.google.com") {
				return errors.New("refusing non-Google SDK download redirect")
			}
			if len(via) >= 5 {
				return errors.New("too many SDK download redirects")
			}
			return nil
		},
	}
}

// googleCommandEnv keeps the user's normal environment while suppressing inherited
// gcloud logging/debug and endpoint overrides. Staging is applied per invocation.
func googleCommandEnv(staging bool) []string {
	values := make(map[string]string)
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "CLOUDSDK_API_ENDPOINT_OVERRIDES_") ||
			upper == "CLOUDSDK_CORE_LOG_HTTP" || upper == "CLOUDSDK_CORE_VERBOSITY" ||
			upper == "CLOUDSDK_CORE_DISABLE_PROMPTS" || upper == "CLOUDSDK_CORE_DISABLE_FILE_LOGGING" ||
			upper == "CLOUDSDK_DEBUG" || upper == "GCLOUD_LOG_HTTP" || upper == "GCLOUD_DEBUG" {
			continue
		}
		values[key] = value
	}
	values["CLOUDSDK_CORE_LOG_HTTP"] = "false"
	values["CLOUDSDK_CORE_VERBOSITY"] = "warning"
	values["CLOUDSDK_CORE_DISABLE_FILE_LOGGING"] = "true"
	// Explicitly override persisted gcloud configuration as well as inherited env.
	values["CLOUDSDK_API_ENDPOINT_OVERRIDES_PUBLICCA"] = "https://publicca.googleapis.com/"
	if staging {
		values["CLOUDSDK_API_ENDPOINT_OVERRIDES_PUBLICCA"] = googleStagingAPIEndpoint
	}
	env := make([]string, 0, len(values))
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}

func googleStaging(c config) bool { return c.acmeDirectory == googleStagingACME }

func googleDirectorySupported(c config) bool {
	return c.acmeDirectory == googleACME || c.acmeDirectory == googleStagingACME
}

func validateGoogleSettings(c config) error {
	if err := c.validate(); err != nil {
		return err
	}
	if !googleDirectorySupported(c) {
		return errors.New("Google setup requires the Google production or staging ACME directory")
	}
	address, err := mail.ParseAddress(c.email)
	if err != nil || address.Address != c.email {
		return errors.New("-email must be a valid plain email address")
	}
	return nil
}

func googleHasActiveAccount(ctx context.Context, gcloud string) (bool, error) {
	var stdout, stderr bytes.Buffer
	args := []string{"auth", "list", "--filter=status:ACTIVE", "--format=value(account)"}
	if err := googleDeps.run(ctx, gcloud, args, googleCommandEnv(false), nil, &stdout, &stderr); err != nil {
		return false, errors.New("could not inspect Google Cloud login status")
	}
	return strings.TrimSpace(stdout.String()) != "", nil
}

func prepareGoogle(ctx context.Context, c config, in io.Reader, out io.Writer) (config, error) {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	var err error
	if strings.TrimSpace(c.domain) == "" {
		c.domain, err = askGoogle(ctx, in, out, "網域名稱（DNS hostname）：")
		if err != nil {
			return c, err
		}
	}
	if strings.TrimSpace(c.email) == "" {
		c.email, err = askGoogle(ctx, in, out, "ACME 帳戶電子郵件：")
		if err != nil {
			return c, err
		}
	}
	c.domain = strings.TrimSpace(c.domain)
	c.email = strings.TrimSpace(c.email)

	// A matching registration is sufficient evidence of prior TOS acceptance;
	// do not install, initialize, list projects, or make cloud changes on restart.
	if c.certDir != "" {
		manager, cacheErr := newCertManager(c)
		if cacheErr != nil {
			return c, cacheErr
		}
		if manager.state.Registration != nil {
			c.acceptTOS = true
			if err := validateGoogleSettings(c); err != nil {
				return c, err
			}
			return c, nil
		}
	}

	if !c.acceptTOS {
		accepted, err := askGoogleYesNo(ctx, in, out, "是否接受憑證機構的服務條款（ACME Terms of Service）？ [y/N]：")
		if err != nil {
			return c, err
		}
		if !accepted {
			return c, errors.New("Google ACME setup cancelled: terms of service were not accepted")
		}
		c.acceptTOS = true
	}
	if err := validateGoogleSettings(c); err != nil {
		return c, err
	}

	gcloud, err := resolveGcloud(c)
	if err != nil {
		if !errors.Is(err, exec.ErrNotFound) {
			return c, errors.New("configured Google Cloud CLI could not be found")
		}
		home, homeErr := googleDeps.homeDir()
		if homeErr != nil || strings.TrimSpace(home) == "" {
			return c, errors.New("could not locate the user home directory for Google Cloud CLI installation")
		}
		target := filepath.Join(home, ".local", "share", "google-cloud-sdk")
		approved, promptErr := askGoogleYesNo(ctx, in, out, fmt.Sprintf("找不到 gcloud。是否下載並安裝 Google Cloud CLI 至 %s？ [y/N]：", target))
		if promptErr != nil {
			return c, promptErr
		}
		if !approved {
			return c, errors.New("Google Cloud CLI installation cancelled")
		}
		gcloud, err = installGoogleCLI(ctx, target, out)
		if err != nil {
			return c, err
		}
	}
	c.gcloudPath = gcloud

	activeAccount, err := googleHasActiveAccount(ctx, gcloud)
	if err != nil {
		return c, err
	}
	if !activeAccount {
		if err := googleDeps.run(ctx, gcloud, []string{"init"}, googleCommandEnv(false), in, out, out); err != nil {
			return c, errors.New("Google Cloud CLI initialization failed")
		}
	}

	projects, err := listGoogleProjects(ctx, gcloud)
	if err != nil {
		return c, err
	}
	selected, err := chooseGoogleProject(ctx, in, out, projects, c.googleProject)
	if err != nil {
		return c, err
	}
	c.googleProject = selected

	if err := googleDeps.run(ctx, gcloud, []string{"services", "enable", "publicca.googleapis.com", "--project=" + selected, "--quiet"}, googleCommandEnv(googleStaging(c)), nil, io.Discard, io.Discard); err != nil {
		return c, errors.New("could not enable the Public CA API in the selected Google Cloud project")
	}
	return c, nil
}

func readGoogleLine(in io.Reader) (string, error) {
	var line strings.Builder
	var one [1]byte
	emptyReads := 0
	for {
		n, err := in.Read(one[:])
		if n > 0 {
			emptyReads = 0
			if one[0] == '\n' {
				return line.String(), nil
			}
			line.WriteByte(one[0])
		}
		if err != nil {
			return line.String(), err
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return line.String(), io.ErrNoProgress
			}
		}
	}
}

func askGoogle(ctx context.Context, in io.Reader, out io.Writer, prompt string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if _, err := io.WriteString(out, prompt); err != nil {
		return "", errors.New("could not display Google setup prompt")
	}
	type inputResult struct {
		line string
		err  error
	}
	result := make(chan inputResult, 1)
	go func() {
		line, err := readGoogleLine(in)
		result <- inputResult{line, err}
	}()
	select {
	case <-ctx.Done():
		// An OS terminal read cannot be cancelled portably. The CLI exits on
		// cancellation; buffering lets the reader finish without blocking.
		return "", ctx.Err()
	case input := <-result:
		if input.err != nil && !errors.Is(input.err, io.EOF) {
			return "", errors.New("could not read Google setup input")
		}
		if errors.Is(input.err, io.EOF) && input.line == "" {
			return "", errors.New("Google setup cancelled: no input")
		}
		return strings.TrimSpace(input.line), nil
	}
}

func askGoogleYesNo(ctx context.Context, in io.Reader, out io.Writer, prompt string) (bool, error) {
	answer, err := askGoogle(ctx, in, out, prompt)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	case "n", "no", "":
		return false, nil
	default:
		return false, errors.New("Google setup cancelled: answer yes or no")
	}
}

func resolveGcloud(c config) (string, error) {
	if c.gcloudPath != "" {
		if strings.ContainsRune(c.gcloudPath, filepath.Separator) {
			info, err := os.Stat(c.gcloudPath)
			if err != nil || info.IsDir() || info.Mode()&0111 == 0 {
				return "", exec.ErrNotFound
			}
			return c.gcloudPath, nil
		}
		return googleDeps.lookPath(c.gcloudPath)
	}
	if p, err := googleDeps.lookPath("gcloud"); err == nil {
		return p, nil
	}
	home, err := googleDeps.homeDir()
	if err != nil {
		return "", exec.ErrNotFound
	}
	p := filepath.Join(home, ".local", "share", "google-cloud-sdk", "bin", "gcloud")
	info, err := os.Stat(p)
	if err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
		return p, nil
	}
	return "", exec.ErrNotFound
}

type googleProject struct {
	ID        string `json:"projectId"`
	Name      string `json:"name"`
	Lifecycle string `json:"lifecycleState"`
}

func listGoogleProjects(ctx context.Context, gcloud string) ([]googleProject, error) {
	var stdout, stderr bytes.Buffer
	err := googleDeps.run(ctx, gcloud, []string{"projects", "list", "--format=json"}, googleCommandEnv(false), nil, &stdout, &stderr)
	if err != nil {
		return nil, errors.New("could not list Google Cloud projects; verify that the signed-in account can list projects")
	}
	var projects []googleProject
	if err := json.Unmarshal(stdout.Bytes(), &projects); err != nil {
		return nil, errors.New("Google Cloud project list response was invalid")
	}
	active := make([]googleProject, 0, len(projects))
	seen := make(map[string]bool, len(projects))
	for _, project := range projects {
		project.ID = strings.TrimSpace(project.ID)
		if project.ID == "" || seen[project.ID] || (project.Lifecycle != "" && project.Lifecycle != "ACTIVE") {
			continue
		}
		seen[project.ID] = true
		active = append(active, project)
	}
	if len(active) == 0 {
		return nil, errors.New("no accessible active Google Cloud projects were found")
	}
	return active, nil
}

func chooseGoogleProject(ctx context.Context, in io.Reader, out io.Writer, projects []googleProject, configured string) (string, error) {
	if configured != "" {
		found := false
		for _, project := range projects {
			if project.ID == configured {
				found = true
				break
			}
		}
		if !found {
			return "", errors.New("configured Google Cloud project is not in the accessible project list")
		}
	} else {
		for i, project := range projects {
			if project.Name != "" {
				fmt.Fprintf(out, "%d) %s (%s)\n", i+1, project.Name, project.ID)
			} else {
				fmt.Fprintf(out, "%d) %s\n", i+1, project.ID)
			}
		}
		answer, err := askGoogle(ctx, in, out, "請輸入專案編號（q 取消）：")
		if err != nil {
			return "", err
		}
		if strings.EqualFold(answer, "q") || strings.EqualFold(answer, "cancel") {
			return "", errors.New("Google project selection cancelled")
		}
		choice, err := strconv.Atoi(answer)
		if err != nil || choice < 1 || choice > len(projects) {
			return "", errors.New("Google project selection must be a listed number")
		}
		configured = projects[choice-1].ID
	}
	confirmed, err := askGoogleYesNo(ctx, in, out, fmt.Sprintf("使用 Google Cloud 專案 %s？ [y/N]：", configured))
	if err != nil {
		return "", err
	}
	if !confirmed {
		return "", errors.New("Google project selection cancelled")
	}
	confirmed, err = askGoogleYesNo(ctx, in, out, fmt.Sprintf("確認只在專案 %s 啟用 Public CA API（publicca.googleapis.com）？ [y/N]：", configured))
	if err != nil {
		return "", err
	}
	if !confirmed {
		return "", errors.New("Google Public CA API enablement cancelled")
	}
	return configured, nil
}

func requestGoogleEAB(ctx context.Context, c config) (kid, hmac string, err error) {
	if c.googleProject == "" || !googleDirectorySupported(c) {
		return "", "", errors.New("Google EAB requires a selected project and Google production or staging directory")
	}
	gcloud, findErr := resolveGcloud(c)
	if findErr != nil {
		return "", "", errors.New("Google Cloud CLI is unavailable for the EAB request")
	}
	var stdout, stderr bytes.Buffer
	args := []string{"publicca", "external-account-keys", "create", "--project=" + c.googleProject, "--format=json"}
	if runErr := googleDeps.run(ctx, gcloud, args, googleCommandEnv(googleStaging(c)), nil, &stdout, &stderr); runErr != nil {
		return "", "", errors.New("Google Public CA external account key request failed")
	}
	var response struct {
		KeyID     string `json:"keyId"`
		B64MacKey string `json:"b64MacKey"`
	}
	if json.Unmarshal(stdout.Bytes(), &response) != nil {
		return "", "", errors.New("Google Public CA external account key response was invalid")
	}
	response.KeyID = strings.TrimSpace(response.KeyID)
	if response.KeyID == "" || len(response.KeyID) > 4096 || strings.IndexFunc(response.KeyID, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return "", "", errors.New("Google Public CA external account key response was invalid")
	}
	mac, ok := decodeEABMAC(response.B64MacKey)
	if !ok || len(mac) < 32 {
		return "", "", errors.New("Google Public CA external account key response was invalid")
	}
	return response.KeyID, base64.RawURLEncoding.EncodeToString(mac), nil
}

func decodeEABMAC(encoded string) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		mac, err := encoding.DecodeString(encoded)
		if err == nil {
			return mac, true
		}
	}
	return nil, false
}

func validEABCredentials(kid, hmac string) bool {
	if kid == "" || len(kid) > 4096 || strings.IndexFunc(kid, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0 {
		return false
	}
	mac, ok := decodeEABMAC(hmac)
	return ok && len(mac) >= 32
}

func googleSDKDownloadURL(goos, goarch string) (string, error) {
	osName := ""
	switch goos {
	case "darwin", "linux":
		osName = goos
	default:
		return "", errors.New("Google Cloud CLI installation supports only darwin and linux")
	}
	arch := ""
	switch goarch {
	case "arm64":
		arch = "arm"
	case "amd64":
		arch = "x86_64"
	default:
		return "", errors.New("Google Cloud CLI installation supports only arm64 and amd64")
	}
	return googleCLIBaseURL + "google-cloud-cli-" + osName + "-" + arch + ".tar.gz", nil
}

func googlePythonAvailable() bool {
	for _, name := range []string{"python3", "python"} {
		if path, err := googleDeps.lookPath(name); err == nil && path != "" {
			return true
		}
	}
	return false
}

func installGoogleCLI(ctx context.Context, target string, out io.Writer) (string, error) {
	url, err := googleSDKDownloadURL(googleDeps.goos, googleDeps.goarch)
	if err != nil {
		return "", err
	}
	if !googlePythonAvailable() {
		return "", errors.New("Google Cloud CLI installation requires a compatible Python 3 installation; install Python 3 and retry")
	}
	if info, err := os.Lstat(target); err == nil {
		if info.IsDir() {
			return "", errors.New("Google Cloud CLI install target already exists; refusing to overwrite")
		}
		return "", errors.New("Google Cloud CLI install target already exists; refusing to overwrite")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("could not inspect Google Cloud CLI install target")
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", errors.New("could not create private Google Cloud CLI installation directory")
	}
	work, err := os.MkdirTemp(parent, ".google-cloud-cli-*")
	if err != nil {
		return "", errors.New("could not create temporary Google Cloud CLI installation directory")
	}
	defer os.RemoveAll(work)

	archivePath := filepath.Join(work, "sdk.tar.gz")
	file, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", errors.New("could not create temporary Google Cloud CLI archive")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		file.Close()
		return "", errors.New("could not prepare Google Cloud CLI download")
	}
	resp, err := googleDeps.http.Do(req)
	if err != nil {
		file.Close()
		return "", errors.New("Google Cloud CLI download failed")
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		file.Close()
		return "", errors.New("Google Cloud CLI download returned an unsuccessful status")
	}
	written, copyErr := io.Copy(file, io.LimitReader(resp.Body, googleCLIArchiveMax+1))
	bodyErr := resp.Body.Close()
	fileErr := file.Close()
	if copyErr != nil || bodyErr != nil || fileErr != nil || written > googleCLIArchiveMax {
		return "", errors.New("Google Cloud CLI download exceeded limits or could not be saved")
	}

	extractRoot := filepath.Join(work, "extract")
	if err := os.Mkdir(extractRoot, 0700); err != nil {
		return "", errors.New("could not prepare Google Cloud CLI extraction directory")
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return "", errors.New("could not open downloaded Google Cloud CLI archive")
	}
	extractErr := extractGoogleSDKArchive(archive, extractRoot)
	closeErr := archive.Close()
	if extractErr != nil || closeErr != nil {
		return "", errors.New("Google Cloud CLI archive was invalid or unsafe")
	}
	sdkRoot := filepath.Join(extractRoot, "google-cloud-sdk")
	installScript := filepath.Join(sdkRoot, "install.sh")
	gcloud := filepath.Join(sdkRoot, "bin", "gcloud")
	if !isExecutableFile(installScript) || !isExecutableFile(gcloud) {
		return "", errors.New("Google Cloud CLI archive did not contain the expected installer")
	}
	if err := os.Chmod(sdkRoot, 0700); err != nil {
		return "", errors.New("could not secure Google Cloud CLI installation")
	}
	installArgs := []string{"--quiet", "--path-update=false", "--command-completion=false", "--usage-reporting=false", "--install-python=false"}
	if err := googleDeps.run(ctx, installScript, installArgs, googleCommandEnv(false), nil, out, out); err != nil {
		return "", errors.New("Google Cloud CLI installer failed; ensure compatible Python 3 is installed")
	}
	if !isExecutableFile(gcloud) {
		return "", errors.New("Google Cloud CLI installer did not produce an executable")
	}
	if _, err := os.Lstat(target); err == nil {
		return "", errors.New("Google Cloud CLI install target appeared during installation; refusing to overwrite")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("could not inspect Google Cloud CLI install target")
	}
	if err := os.Rename(sdkRoot, target); err != nil {
		return "", errors.New("could not atomically install Google Cloud CLI")
	}
	return filepath.Join(target, "bin", "gcloud"), nil
}

func isExecutableFile(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir() && info.Mode()&0111 != 0
}

func extractGoogleSDKArchive(src io.Reader, dest string) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return errors.New("invalid gzip")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var expanded int64
	entries := 0
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("invalid tar archive")
		}
		entries++
		if entries > googleCLIEntryMax || header.Size < 0 || header.Size > googleCLIExpandedMax-expanded {
			return errors.New("archive limit exceeded")
		}
		expanded += header.Size
		name := strings.ReplaceAll(header.Name, "\\", "/")
		clean := path.Clean(name)
		if name == "" || strings.HasPrefix(name, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
			return errors.New("unsafe archive path")
		}
		target := filepath.Join(dest, filepath.FromSlash(clean))
		rel, err := filepath.Rel(dest, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return errors.New("unsafe archive path")
		}
		if err := ensureSafeArchiveParents(dest, filepath.Dir(target)); err != nil {
			return err
		}
		mode := os.FileMode(header.Mode).Perm() & 0755
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(target, 0755); err != nil && !errors.Is(err, os.ErrExist) {
				return errors.New("could not create archive directory")
			}
			info, err := os.Lstat(target)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("unsafe archive directory")
			}
		case tar.TypeReg, tar.TypeRegA:
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return errors.New("could not create archive file")
			}
			_, copyErr := io.CopyN(file, tr, header.Size)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil {
				return errors.New("could not extract archive file")
			}
			if err := os.Chmod(target, mode); err != nil {
				return errors.New("could not set archive file mode")
			}
		case tar.TypeSymlink:
			link := strings.ReplaceAll(header.Linkname, "\\", "/")
			if link == "" || strings.HasPrefix(link, "/") {
				return errors.New("unsafe archive symlink")
			}
			resolved := path.Clean(path.Join(path.Dir(clean), link))
			if resolved == ".." || strings.HasPrefix(resolved, "../") || path.IsAbs(resolved) {
				return errors.New("unsafe archive symlink")
			}
			if err := os.Symlink(filepath.FromSlash(link), target); err != nil {
				return errors.New("could not create archive symlink")
			}
		default:
			return errors.New("unsupported special archive entry")
		}
	}
	return nil
}

func ensureSafeArchiveParents(root, parent string) error {
	rel, err := filepath.Rel(root, parent)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return errors.New("unsafe archive path")
	}
	current := root
	if rel == "." {
		return nil
	}
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0755); err != nil {
				return errors.New("could not create archive parent")
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe archive parent")
		}
	}
	return nil
}
