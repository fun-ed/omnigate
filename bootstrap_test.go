package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/registration"
)

func replaceGoogleDeps(t *testing.T, run googleCommandRunner) {
	t.Helper()
	original := googleDeps
	googleDeps = googleBootstrapDeps{
		run: run,
		lookPath: func(name string) (string, error) {
			if name == "gcloud" || name == "fake-gcloud" {
				return "fake-gcloud", nil
			}
			return "", os.ErrNotExist
		},
		homeDir: func() (string, error) { return t.TempDir(), nil },
		http:    newGoogleHTTPClient(),
		goos:    "darwin",
		goarch:  "arm64",
	}
	t.Cleanup(func() { googleDeps = original })
}

func googleTestConfig(t *testing.T) config {
	t.Helper()
	return config{
		httpAddr:       ":8080",
		httpsAddr:      ":443",
		domain:         "example.com",
		email:          "admin@example.com",
		acmeDirectory:  googleACME,
		certDir:        filepath.Join(t.TempDir(), "certs"),
		healthPath:     "/healthz",
		burst:          1,
		healthInterval: time.Second,
		acceptTOS:      true,
		gcloudPath:     "fake-gcloud",
	}
}

func TestPrepareGoogleSelectsAndConfirmsProjectScope(t *testing.T) {
	var commands [][]string
	run := func(_ context.Context, _ string, args []string, _ []string, _ io.Reader, stdout, _ io.Writer) error {
		commands = append(commands, append([]string(nil), args...))
		if len(args) == 3 && args[0] == "projects" {
			_, _ = io.WriteString(stdout, `[{"projectId":"alpha","name":"Alpha","lifecycleState":"ACTIVE"},{"projectId":"beta","lifecycleState":"ACTIVE"}]`)
		}
		return nil
	}
	replaceGoogleDeps(t, run)
	c := googleTestConfig(t)
	got, err := prepareGoogle(context.Background(), c, strings.NewReader("2\nyes\nyes\n"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got.googleProject != "beta" {
		t.Fatalf("selected project = %q, want beta", got.googleProject)
	}
	if len(commands) != 4 ||
		strings.Join(commands[0], " ") != "auth list --filter=status:ACTIVE --format=value(account)" ||
		strings.Join(commands[1], " ") != "init" ||
		strings.Join(commands[2], " ") != "projects list --format=json" {
		t.Fatalf("unexpected command sequence: %#v", commands)
	}
	wantEnable := "services enable publicca.googleapis.com --project=beta --quiet"
	if strings.Join(commands[3], " ") != wantEnable {
		t.Fatalf("enable command = %q, want %q", strings.Join(commands[3], " "), wantEnable)
	}
}

func TestPrepareGooglePromptsForMissingSettingsAndTOS(t *testing.T) {
	run := func(_ context.Context, _ string, args []string, _ []string, _ io.Reader, stdout, _ io.Writer) error {
		if strings.Join(args, " ") == "projects list --format=json" {
			_, _ = io.WriteString(stdout, `[{"projectId":"selected","lifecycleState":"ACTIVE"}]`)
		}
		return nil
	}
	replaceGoogleDeps(t, run)
	c := googleTestConfig(t)
	c.domain, c.email, c.acceptTOS = "", "", false
	input := "example.com\nadmin@example.com\nyes\n1\nyes\nyes\n"
	got, err := prepareGoogle(context.Background(), c, strings.NewReader(input), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got.domain != "example.com" || got.email != "admin@example.com" || !got.acceptTOS {
		t.Fatalf("prompted settings were not retained: domain=%q email=%q acceptTOS=%v", got.domain, got.email, got.acceptTOS)
	}
}

func TestPrepareGooglePassesOriginalReaderToGcloudInit(t *testing.T) {
	input := strings.NewReader("1\nyes\nyes\n")
	var initInput io.Reader
	run := func(_ context.Context, _ string, args []string, _ []string, stdin io.Reader, stdout, _ io.Writer) error {
		if len(args) == 1 && args[0] == "init" {
			initInput = stdin
		}
		if strings.Join(args, " ") == "projects list --format=json" {
			_, _ = io.WriteString(stdout, `[{"projectId":"selected","lifecycleState":"ACTIVE"}]`)
		}
		return nil
	}
	replaceGoogleDeps(t, run)
	if _, err := prepareGoogle(context.Background(), googleTestConfig(t), input, io.Discard); err != nil {
		t.Fatal(err)
	}
	if initInput != input {
		t.Fatal("gcloud init did not receive the original unbuffered input reader")
	}
}

func TestPrepareGoogleReusesActiveGcloudLogin(t *testing.T) {
	var commands [][]string
	var authStdin io.Reader
	run := func(_ context.Context, _ string, args []string, _ []string, stdin io.Reader, stdout, _ io.Writer) error {
		commands = append(commands, append([]string(nil), args...))
		switch strings.Join(args, " ") {
		case "auth list --filter=status:ACTIVE --format=value(account)":
			authStdin = stdin
			_, _ = io.WriteString(stdout, "active@example.com\n")
		case "projects list --format=json":
			_, _ = io.WriteString(stdout, `[{"projectId":"selected","lifecycleState":"ACTIVE"}]`)
		}
		return nil
	}
	replaceGoogleDeps(t, run)
	input := strings.NewReader("1\nyes\nyes\n")
	got, err := prepareGoogle(context.Background(), googleTestConfig(t), input, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if authStdin != nil {
		t.Fatal("gcloud auth status check should not consume interactive input")
	}
	if got.googleProject != "selected" {
		t.Fatalf("selected project = %q, want selected", got.googleProject)
	}
	if len(commands) != 3 ||
		strings.Join(commands[0], " ") != "auth list --filter=status:ACTIVE --format=value(account)" ||
		strings.Join(commands[1], " ") != "projects list --format=json" {
		t.Fatalf("active login should skip init: %#v", commands)
	}
}

func TestPrepareGoogleProjectSelectionCanCancel(t *testing.T) {
	var commands [][]string
	run := func(_ context.Context, _ string, args []string, _ []string, _ io.Reader, stdout, _ io.Writer) error {
		commands = append(commands, append([]string(nil), args...))
		if strings.Join(args, " ") == "projects list --format=json" {
			_, _ = io.WriteString(stdout, `[{"projectId":"alpha","lifecycleState":"ACTIVE"}]`)
		}
		return nil
	}
	replaceGoogleDeps(t, run)
	_, err := prepareGoogle(context.Background(), googleTestConfig(t), strings.NewReader("q\n"), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("prepareGoogle error = %v, want project cancellation", err)
	}
	for _, args := range commands {
		if len(args) > 1 && args[0] == "services" {
			t.Fatal("API enable command ran after project selection was cancelled")
		}
	}
}

func TestPrepareGoogleRejectsUnlistedConfiguredProject(t *testing.T) {
	var commands [][]string
	run := func(_ context.Context, _ string, args []string, _ []string, _ io.Reader, stdout, _ io.Writer) error {
		commands = append(commands, append([]string(nil), args...))
		if strings.Join(args, " ") == "projects list --format=json" {
			_, _ = io.WriteString(stdout, `[{"projectId":"listed","lifecycleState":"ACTIVE"}]`)
		}
		return nil
	}
	replaceGoogleDeps(t, run)
	c := googleTestConfig(t)
	c.googleProject = "not-listed"
	_, err := prepareGoogle(context.Background(), c, strings.NewReader(""), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not in the accessible project list") {
		t.Fatalf("prepareGoogle error = %v, want configured-project validation error", err)
	}
	for _, args := range commands {
		if len(args) > 1 && args[0] == "services" {
			t.Fatal("API enable command ran for an unlisted project")
		}
	}
}

func TestPrepareGoogleMatchingRegistrationSkipsAllCommands(t *testing.T) {
	runCalls := 0
	replaceGoogleDeps(t, func(context.Context, string, []string, []string, io.Reader, io.Writer, io.Writer) error {
		runCalls++
		return errors.New("unexpected command")
	})
	c := googleTestConfig(t)
	if err := os.MkdirAll(c.certDir, 0700); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	accountKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	state, err := json.Marshal(acmeState{
		Directory:    c.acmeDirectory,
		Domain:       c.domain,
		Email:        c.email,
		AccountKey:   accountKey,
		Registration: &registration.Resource{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.certDir, "state.json"), state, 0600); err != nil {
		t.Fatal(err)
	}
	c.acceptTOS = false
	got, err := prepareGoogle(context.Background(), c, strings.NewReader(""), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if runCalls != 0 {
		t.Fatalf("Google command calls = %d, want 0", runCalls)
	}
	if !got.acceptTOS {
		t.Fatal("matching registration should carry forward prior TOS acceptance")
	}
}

func TestRequestGoogleEABCapturesJSONAndUsesExplicitProject(t *testing.T) {
	const kid = "eab-key-id"
	mac := googleEABTestMAC(t)
	const leaked = "stderr-must-not-be-returned"
	var gotArgs []string
	var gotEnv []string
	replaceGoogleDeps(t, func(_ context.Context, _ string, args, env []string, _ io.Reader, stdout, stderr io.Writer) error {
		gotArgs = append([]string(nil), args...)
		gotEnv = append([]string(nil), env...)
		_, _ = io.WriteString(stdout, `{"keyId":"`+kid+`","b64MacKey":"`+mac+`"}`)
		_, _ = io.WriteString(stderr, leaked)
		return nil
	})
	c := googleTestConfig(t)
	c.googleProject = "project-123"
	gotKid, gotMAC, err := requestGoogleEAB(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if gotKid != kid || gotMAC != mac {
		t.Fatalf("EAB = (%q, %q), want (%q, %q)", gotKid, gotMAC, kid, mac)
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, "--project=project-123") || !strings.Contains(joined, "--format=json") {
		t.Fatalf("EAB command lacks explicit project/JSON format: %q", joined)
	}
	if strings.Contains(strings.Join(gotEnv, "\n"), "LOG_HTTP=true") || strings.Contains(strings.Join(gotEnv, "\n"), "VERBOSITY=debug") {
		t.Fatal("unsafe inherited gcloud logging environment was retained")
	}

	replaceGoogleDeps(t, func(_ context.Context, _ string, _ []string, _ []string, _ io.Reader, stdout, stderr io.Writer) error {
		_, _ = io.WriteString(stdout, `{"keyId":"`+kid+`","b64MacKey":"`+mac+`"}`)
		_, _ = io.WriteString(stderr, leaked)
		return fmt.Errorf("fake failure containing %s", leaked)
	})
	gotKid, gotMAC, err = requestGoogleEAB(context.Background(), c)
	if err == nil || gotKid != "" || gotMAC != "" || strings.Contains(err.Error(), leaked) {
		t.Fatalf("failed EAB result leaked output: kid=%q mac=%q err=%v", gotKid, gotMAC, err)
	}
}

func TestRequestGoogleEABNormalizesStandardBase64(t *testing.T) {
	stdMac := base64.StdEncoding.EncodeToString(googleEABTestKey())
	replaceGoogleDeps(t, func(_ context.Context, _ string, _ []string, _ []string, _ io.Reader, stdout, _ io.Writer) error {
		_, _ = io.WriteString(stdout, `{"keyId":"key","b64MacKey":"`+stdMac+`"}`)
		return nil
	})
	c := googleTestConfig(t)
	c.googleProject = "project-123"
	_, gotMAC, err := requestGoogleEAB(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	want := base64.RawURLEncoding.EncodeToString(googleEABTestKey())
	if gotMAC != want {
		t.Fatalf("normalized HMAC = %q, want %q", gotMAC, want)
	}
}

func TestGoogleCommandEnvUsesStagingEndpointPerCommand(t *testing.T) {
	if googleStagingAPIEndpoint != "https://preprod-publicca.googleapis.com/" {
		t.Fatalf("staging Public CA endpoint = %q", googleStagingAPIEndpoint)
	}
	t.Setenv("CLOUDSDK_API_ENDPOINT_OVERRIDES_PUBLICCA", "https://attacker.invalid/")
	t.Setenv("CLOUDSDK_CORE_DISABLE_FILE_LOGGING", "false")
	production := strings.Join(googleCommandEnv(false), "\n")
	if strings.Contains(production, "attacker.invalid") {
		t.Fatal("inherited API endpoint override was not removed")
	}
	if !strings.Contains(production, "CLOUDSDK_API_ENDPOINT_OVERRIDES_PUBLICCA=https://publicca.googleapis.com/") {
		t.Fatal("production endpoint must override persisted staging/custom gcloud configuration")
	}
	if !strings.Contains(production, "CLOUDSDK_CORE_DISABLE_FILE_LOGGING=true") {
		t.Fatal("gcloud file logging was not disabled")
	}
	staging := strings.Join(googleCommandEnv(true), "\n")
	if !strings.Contains(staging, "CLOUDSDK_API_ENDPOINT_OVERRIDES_PUBLICCA="+googleStagingAPIEndpoint) {
		t.Fatal("staging endpoint override was not set for the command")
	}
}

func TestGoogleHTTPClientHasBoundedTimeout(t *testing.T) {
	if got := newGoogleHTTPClient().Timeout; got != 5*time.Minute {
		t.Fatalf("HTTP timeout = %s, want 5m", got)
	}
}

func TestGoogleSDKDownloadURLDarwinArm64(t *testing.T) {
	got, err := googleSDKDownloadURL("darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-darwin-arm.tar.gz"
	if got != want {
		t.Fatalf("download URL = %q, want %q", got, want)
	}
}

func TestGoogleSDKArchiveRejectsTraversalAndSymlinkEscape(t *testing.T) {
	for _, tc := range []struct {
		name    string
		header  tar.Header
		content string
	}{
		{name: "path traversal", header: tar.Header{Name: "../outside", Typeflag: tar.TypeReg, Mode: 0600, Size: 4}, content: "nope"},
		{name: "symlink escape", header: tar.Header{Name: "google-cloud-sdk/escape", Typeflag: tar.TypeSymlink, Linkname: "../../outside", Mode: 0777}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := makeGoogleTarGz(t, []struct {
				header  tar.Header
				content string
			}{{header: tc.header, content: tc.content}})
			dest := t.TempDir()
			if err := extractGoogleSDKArchive(bytes.NewReader(archive), dest); err == nil {
				t.Fatal("unsafe archive was accepted")
			}
			if _, err := os.Lstat(filepath.Join(filepath.Dir(dest), "outside")); err == nil {
				t.Fatal("archive created a path outside extraction root")
			}
		})
	}
}

func TestOfficialSDKArchiveExtraction(t *testing.T) {
	archivePath := os.Getenv("WEB_HTTP_TEST_SDK_ARCHIVE")
	if archivePath == "" {
		t.Skip("set WEB_HTTP_TEST_SDK_ARCHIVE to exercise a downloaded official SDK archive")
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	extractErr := extractGoogleSDKArchive(archive, dest)
	closeErr := archive.Close()
	if extractErr != nil {
		t.Fatal(extractErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	sdkRoot := filepath.Join(dest, "google-cloud-sdk")
	if !isExecutableFile(filepath.Join(sdkRoot, "install.sh")) || !isExecutableFile(filepath.Join(sdkRoot, "bin", "gcloud")) {
		t.Fatal("official SDK archive is missing executable installer or gcloud")
	}
}

func TestInstallGoogleCLIUsesOfficialDarwinArm64URL(t *testing.T) {
	archive := makeGoogleTarGz(t, []struct {
		header  tar.Header
		content string
	}{
		{header: tar.Header{Name: "google-cloud-sdk/install.sh", Typeflag: tar.TypeReg, Mode: 0755, Size: int64(len("#!/bin/sh\n"))}, content: "#!/bin/sh\n"},
		{header: tar.Header{Name: "google-cloud-sdk/bin/gcloud", Typeflag: tar.TypeReg, Mode: 0755, Size: int64(len("#!/bin/sh\n"))}, content: "#!/bin/sh\n"},
	})
	var requestedURL string
	original := googleDeps
	googleDeps = googleBootstrapDeps{
		run: func(_ context.Context, executable string, args []string, _ []string, _ io.Reader, _ io.Writer, _ io.Writer) error {
			if !strings.HasSuffix(executable, filepath.Join("google-cloud-sdk", "install.sh")) {
				t.Fatalf("installer executable = %q", executable)
			}
			if strings.Join(args, " ") != "--quiet --path-update=false --command-completion=false --usage-reporting=false --install-python=false" {
				t.Fatalf("installer arguments = %#v", args)
			}
			return nil
		},
		lookPath: func(name string) (string, error) {
			if name == "python3" {
				return "/usr/bin/python3", nil
			}
			return "", os.ErrNotExist
		},
		homeDir: func() (string, error) { return t.TempDir(), nil },
		http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requestedURL = req.URL.String()
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(archive)), Request: req}, nil
		})},
		goos:   "darwin",
		goarch: "arm64",
	}
	t.Cleanup(func() { googleDeps = original })
	target := filepath.Join(t.TempDir(), "private", "google-cloud-sdk")
	gcloud, err := installGoogleCLI(context.Background(), target, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	wantURL := "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-darwin-arm.tar.gz"
	if requestedURL != wantURL {
		t.Fatalf("requested URL = %q, want %q", requestedURL, wantURL)
	}
	if gcloud != filepath.Join(target, "bin", "gcloud") || !isExecutableFile(gcloud) {
		t.Fatalf("installed gcloud path = %q, expected executable under target", gcloud)
	}
}

func TestInstallGoogleCLIMissingPythonFailsBeforeDownload(t *testing.T) {
	original := googleDeps
	downloaded := false
	googleDeps = googleBootstrapDeps{
		run: func(context.Context, string, []string, []string, io.Reader, io.Writer, io.Writer) error {
			t.Fatal("installer ran without a Python installation")
			return nil
		},
		lookPath: func(string) (string, error) { return "", os.ErrNotExist },
		homeDir:  func() (string, error) { return t.TempDir(), nil },
		http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			downloaded = true
			return nil, errors.New("unexpected download")
		})},
		goos:   "darwin",
		goarch: "arm64",
	}
	t.Cleanup(func() { googleDeps = original })
	target := filepath.Join(t.TempDir(), "private", "google-cloud-sdk")
	_, err := installGoogleCLI(context.Background(), target, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "Python 3") {
		t.Fatalf("install error = %v, want Python 3 prerequisite", err)
	}
	if downloaded {
		t.Fatal("SDK download started without a Python installation")
	}
}

func googleEABTestKey() []byte {
	return bytes.Repeat([]byte{0xfb, 0xff}, 16)
}

func googleEABTestMAC(t *testing.T) string {
	t.Helper()
	encoded := base64.RawURLEncoding.EncodeToString(googleEABTestKey())
	if !strings.Contains(encoded, "-") || !strings.Contains(encoded, "_") {
		t.Fatalf("test fixture does not cover URL-safe base64 characters: %q", encoded)
	}
	return encoded
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func makeGoogleTarGz(t *testing.T, entries []struct {
	header  tar.Header
	content string
}) []byte {
	t.Helper()
	var result bytes.Buffer
	gz := gzip.NewWriter(&result)
	tarWriter := tar.NewWriter(gz)
	for _, entry := range entries {
		header := entry.header
		if err := tarWriter.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if entry.content != "" {
			if _, err := io.WriteString(tarWriter, entry.content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

func TestRequestGoogleEABUsesStagingEndpointOverride(t *testing.T) {
	var gotEnv []string
	mac := googleEABTestMAC(t)
	replaceGoogleDeps(t, func(_ context.Context, _ string, _ []string, env []string, _ io.Reader, stdout, _ io.Writer) error {
		gotEnv = append([]string(nil), env...)
		_, _ = io.WriteString(stdout, `{"keyId":"key","b64MacKey":"`+mac+`"}`)
		return nil
	})
	c := googleTestConfig(t)
	c.acmeDirectory = googleStagingACME
	c.googleProject = "project-123"
	if _, _, err := requestGoogleEAB(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(gotEnv, "\n"), "CLOUDSDK_API_ENDPOINT_OVERRIDES_PUBLICCA="+googleStagingAPIEndpoint) {
		t.Fatal("EAB command did not receive its per-command staging endpoint override")
	}
}
