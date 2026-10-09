#!/usr/bin/env python3
"""Local tunnel fixture and HTTP/WS acceptance probe."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO, Callable
from urllib.parse import urlsplit

MAX_FRAME_BYTES = 1024 * 1024
MAX_HTTP_BODY_BYTES = 1024 * 1024
MAX_HANDSHAKE_BYTES = 64 * 1024
MAX_MARKER_BYTES = 4096
DEFAULT_TIMEOUT = 5.0
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_AUTH_HEADER_RE = re.compile(r"(?i)(authorization\s*[:=]\s*)[^\r\n,;]+")


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    host: str
    port: int

    @property
    def is_tls(self) -> bool:
        return self.scheme == "https"

    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default_port = 443 if self.is_tls else 80
        return host if self.port == default_port else f"{host}:{self.port}"


class CheckFailure(Exception):
    """An expected, safe-to-report acceptance-check failure."""


class WebSocketProtocolError(Exception):
    """A safe protocol error without any request or credential data."""


@dataclass(frozen=True)
class WebSocketFrame:
    opcode: int
    payload: bytes
    fin: bool
    masked: bool


def validate_marker(marker: str) -> str:
    if not marker or len(marker.encode("utf-8")) > MAX_MARKER_BYTES:
        raise ValueError("marker must be non-empty and at most 4096 UTF-8 bytes")
    return marker


def _validate_url_text(value: str) -> None:
    if not value or len(value) > 2048 or any(ord(char) <= 32 or char == "\\" for char in value):
        raise ValueError("invalid URL")


def _url_parts(value: str):
    _validate_url_text(value)
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ValueError("invalid URL") from None
    if not parts.hostname or "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise ValueError("URL must have a hostname and no userinfo")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("URL must be an origin without path, query, or fragment")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("URL port must be between 1 and 65535")
    return parts, port


def validate_origin(value: str) -> Endpoint:
    """Validate an HTTP origin whose host is an IP literal in loopback space."""
    parts, port = _url_parts(value)
    if parts.scheme.lower() != "http":
        raise ValueError("origin must use http")
    host = parts.hostname
    if "%" in host:
        raise ValueError("origin must use a loopback IP literal")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("origin must use a loopback IP literal") from None
    if not address.is_loopback:
        raise ValueError("origin must be loopback")
    return Endpoint("http", str(address), port or 80)


def _canonical_public_host(host: str) -> str:
    if "%" in host:
        raise ValueError("invalid public hostname")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("invalid public hostname") from None
    if len(ascii_host) > 253 or not ascii_host or any(
        not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in ascii_host.rstrip(".").split(".")
    ):
        raise ValueError("invalid public hostname")
    return ascii_host


def validate_public(value: str) -> Endpoint:
    """Validate an HTTPS public origin without credentials or URL parameters."""
    parts, port = _url_parts(value)
    if parts.scheme.lower() != "https":
        raise ValueError("public URL must use https")
    return Endpoint("https", _canonical_public_host(parts.hostname), port or 443)


def basic_authorization(user: str, password: str) -> str:
    if not user or ":" in user or any(ord(char) < 32 or ord(char) == 127 for char in user):
        raise ValueError("user must be non-empty and contain no colon or control characters")
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def sanitize_error(message: object, secrets_to_redact: tuple[str, ...] | list[str] = ()) -> str:
    """Remove supplied secret values and Authorization fields from free-form text."""
    text = _AUTH_HEADER_RE.sub(r"\1[REDACTED]", str(message))
    for secret in sorted((item for item in secrets_to_redact if item), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text[:300]


def _safe_exception_message(error: BaseException) -> str:
    if isinstance(error, CheckFailure):
        return str(error)
    if isinstance(error, WebSocketProtocolError):
        return str(error)
    if isinstance(error, ssl.SSLCertVerificationError):
        return "TLS certificate verification failed"
    if isinstance(error, ssl.SSLError):
        return "TLS connection failed"
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "network request timed out"
    if isinstance(error, socket.gaierror):
        return "DNS resolution failed"
    if isinstance(error, (OSError, http.client.HTTPException)):
        return "network connection failed"
    if isinstance(error, (ValueError, UnicodeError, json.JSONDecodeError)):
        return "invalid response"
    return f"request failed ({type(error).__name__})"


def _read_exact(stream: BinaryIO, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = stream.read(count - len(chunks))
        if not chunk:
            raise WebSocketProtocolError("unexpected end of WebSocket frame")
        chunks.extend(chunk)
    return bytes(chunks)


def encode_ws_frame(
    opcode: int,
    payload: bytes,
    *,
    masked: bool,
    fin: bool = True,
    mask_key: bytes | None = None,
) -> bytes:
    """Encode one RFC6455 frame, enforcing frame and control payload limits."""
    if not 0 <= opcode <= 15:
        raise ValueError("invalid WebSocket opcode")
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError("WebSocket payload exceeds limit")
    if opcode >= 8 and (not fin or len(payload) > 125):
        raise ValueError("invalid WebSocket control frame")
    first = (0x80 if fin else 0) | opcode
    mask_flag = 0x80 if masked else 0
    length = len(payload)
    if length < 126:
        header = bytes((first, mask_flag | length))
    elif length <= 0xFFFF:
        header = bytes((first, mask_flag | 126)) + length.to_bytes(2, "big")
    else:
        header = bytes((first, mask_flag | 127)) + length.to_bytes(8, "big")
    if not masked:
        return header + payload
    key = mask_key if mask_key is not None else os.urandom(4)
    if len(key) != 4:
        raise ValueError("WebSocket mask key must be 4 bytes")
    masked_payload = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return header + key + masked_payload


def read_ws_frame(stream: BinaryIO, *, require_mask: bool | None = None) -> WebSocketFrame:
    """Read and validate a single RFC6455 frame with bounded allocation."""
    first, second = _read_exact(stream, 2)
    fin = bool(first & 0x80)
    if first & 0x70:
        raise WebSocketProtocolError("WebSocket reserved bits are set")
    opcode = first & 0x0F
    if opcode not in (0, 1, 2, 8, 9, 10):
        raise WebSocketProtocolError("unsupported WebSocket opcode")
    masked = bool(second & 0x80)
    if require_mask is not None and masked != require_mask:
        raise WebSocketProtocolError("unexpected WebSocket masking")
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(_read_exact(stream, 2), "big")
        if length < 126:
            raise WebSocketProtocolError("non-canonical WebSocket length")
    elif length == 127:
        length = int.from_bytes(_read_exact(stream, 8), "big")
        if length < 65536 or length & (1 << 63):
            raise WebSocketProtocolError("invalid WebSocket length")
    if length > MAX_FRAME_BYTES:
        raise WebSocketProtocolError("WebSocket payload exceeds limit")
    if opcode >= 8 and (not fin or length > 125):
        raise WebSocketProtocolError("invalid WebSocket control frame")
    mask_key = _read_exact(stream, 4) if masked else b""
    payload = _read_exact(stream, length)
    if masked:
        payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
    return WebSocketFrame(opcode=opcode, payload=payload, fin=fin, masked=masked)


def _send_ws_frame(writer: BinaryIO | socket.socket, opcode: int, payload: bytes, *, masked: bool = False) -> None:
    frame = encode_ws_frame(opcode, payload, masked=masked)
    if isinstance(writer, socket.socket):
        writer.sendall(frame)
    else:
        writer.write(frame)
        writer.flush()


def _validated_external_scheme(endpoint: Endpoint, external_scheme: str | None) -> str | None:
    if external_scheme is None:
        return None
    if external_scheme not in ("http", "https"):
        raise ValueError("external scheme must be http or https")
    if endpoint.scheme != "http":
        raise ValueError("external scheme override requires an HTTP origin")
    if "%" in endpoint.host or not 1 <= endpoint.port <= 65535:
        raise ValueError("external scheme override requires a validated loopback origin")
    try:
        address = ipaddress.ip_address(endpoint.host)
    except ValueError:
        raise ValueError("external scheme override requires a loopback origin") from None
    if not address.is_loopback or str(address) != endpoint.host:
        raise ValueError("external scheme override requires a validated loopback origin")
    return external_scheme


def http_request(
    endpoint: Endpoint,
    path: str,
    *,
    authorization: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    external_scheme: str | None = None,
) -> tuple[int, bytes]:
    """Perform one bounded HTTP request without following redirects."""
    external_scheme = _validated_external_scheme(endpoint, external_scheme)
    connection_type = http.client.HTTPSConnection if endpoint.is_tls else http.client.HTTPConnection
    if endpoint.is_tls:
        connection = connection_type(
            endpoint.host,
            endpoint.port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
    else:
        connection = connection_type(endpoint.host, endpoint.port, timeout=timeout)
    headers = {"Host": endpoint.host_header(), "Connection": "close", "Accept": "application/json"}
    if authorization is not None:
        headers["Authorization"] = authorization
    if external_scheme is not None:
        headers["X-Forwarded-Proto"] = external_scheme
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(MAX_HTTP_BODY_BYTES + 1)
        if len(body) > MAX_HTTP_BODY_BYTES:
            raise CheckFailure("HTTP response body exceeds limit")
        return response.status, body
    finally:
        connection.close()

def _websocket_path(endpoint: Endpoint) -> str:
    return "/socket"


def _read_handshake_line(stream: BinaryIO) -> bytes:
    line = stream.readline(MAX_HANDSHAKE_BYTES + 1)
    if not line or len(line) > MAX_HANDSHAKE_BYTES:
        raise WebSocketProtocolError("invalid WebSocket handshake")
    return line


def websocket_echo(
    endpoint: Endpoint,
    *,
    authorization: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    nonce: str | None = None,
    ping_payload: bytes | None = None,
    external_scheme: str | None = None,
) -> None:
    """Validate an RFC6455 upgrade and exchange two masked text frames."""
    external_scheme = _validated_external_scheme(endpoint, external_scheme)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    sock = socket.create_connection((endpoint.host, endpoint.port), timeout=timeout)
    stream: BinaryIO | None = None
    try:
        if endpoint.is_tls:
            context = ssl.create_default_context()
            context.set_alpn_protocols(["http/1.1"])
            sock = context.wrap_socket(sock, server_hostname=endpoint.host)
            sock.settimeout(timeout)
        stream = sock.makefile("rb")
        request_lines = [
            f"GET {_websocket_path(endpoint)} HTTP/1.1",
            f"Host: {endpoint.host_header()}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        if authorization is not None:
            request_lines.append(f"Authorization: {authorization}")
        if external_scheme is not None:
            request_lines.append(f"X-Forwarded-Proto: {external_scheme}")
        request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii")
        sock.sendall(request)

        status_line = _read_handshake_line(stream).decode("iso-8859-1").rstrip("\r\n")
        status_parts = status_line.split(" ", 2)
        if len(status_parts) < 2 or not status_parts[1].isdigit():
            raise WebSocketProtocolError("invalid WebSocket handshake")
        status = int(status_parts[1])
        headers: dict[str, list[str]] = {}
        total_header_bytes = len(status_line)
        while True:
            raw_line = _read_handshake_line(stream)
            total_header_bytes += len(raw_line)
            if total_header_bytes > MAX_HANDSHAKE_BYTES:
                raise WebSocketProtocolError("WebSocket handshake headers exceed limit")
            if raw_line in (b"\r\n", b"\n"):
                break
            try:
                name, value = raw_line.decode("iso-8859-1").split(":", 1)
            except ValueError:
                raise WebSocketProtocolError("invalid WebSocket handshake headers") from None
            headers.setdefault(name.strip().lower(), []).append(value.strip())
        if status != 101:
            raise WebSocketProtocolError(f"WebSocket upgrade returned HTTP {status}")
        connection_tokens = {
            item.strip().lower()
            for value in headers.get("connection", [])
            for item in value.split(",")
        }
        upgrade_tokens = {item.strip().lower() for value in headers.get("upgrade", []) for item in value.split(",")}
        expected_accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()).decode("ascii")
        if "upgrade" not in connection_tokens or "websocket" not in upgrade_tokens:
            raise WebSocketProtocolError("invalid WebSocket upgrade headers")
        if headers.get("sec-websocket-accept") != [expected_accept]:
            raise WebSocketProtocolError("invalid Sec-WebSocket-Accept")

        if nonce is None:
            nonce = secrets.token_hex(16)
        frames = (f"tunnel-acceptance:{nonce}:1", f"tunnel-acceptance:{nonce}:2")
        if ping_payload is not None:
            if len(ping_payload) > 125:
                raise ValueError("ping payload exceeds WebSocket control-frame limit")
            _send_ws_frame(sock, 9, ping_payload, masked=True)
            while True:
                frame = read_ws_frame(stream, require_mask=False)
                if frame.opcode == 10 and frame.payload == ping_payload:
                    break
                if frame.opcode == 9:
                    _send_ws_frame(sock, 10, frame.payload, masked=True)
                    continue
                if frame.opcode == 8:
                    raise WebSocketProtocolError("WebSocket closed during ping check")
                raise WebSocketProtocolError("unexpected WebSocket frame during ping check")
        for expected_text in frames:
            expected = expected_text.encode("utf-8")
            _send_ws_frame(sock, 1, expected, masked=True)
            while True:
                frame = read_ws_frame(stream, require_mask=False)
                if frame.opcode == 9:
                    _send_ws_frame(sock, 10, frame.payload, masked=True)
                    continue
                if frame.opcode == 8:
                    raise WebSocketProtocolError("WebSocket closed before echo completed")
                if frame.opcode != 1 or not frame.fin:
                    raise WebSocketProtocolError("expected a final WebSocket text frame")
                try:
                    frame.payload.decode("utf-8")
                except UnicodeDecodeError:
                    raise WebSocketProtocolError("server sent invalid UTF-8 text") from None
                if frame.payload != expected:
                    raise WebSocketProtocolError("WebSocket echo payload did not match")
                break
        _send_ws_frame(sock, 8, (1000).to_bytes(2, "big"), masked=True)
    finally:
        if stream is not None:
            try:
                stream.close()
            finally:
                sock.close()
        else:
            sock.close()


def _check_http_status(
    endpoint: Endpoint,
    path: str,
    expected_status: int,
    *,
    authorization: str | None,
    timeout: float,
    external_scheme: str | None = None,
) -> None:
    status, _body = http_request(
        endpoint, path, authorization=authorization, timeout=timeout, external_scheme=external_scheme
    )
    if status != expected_status:
        raise CheckFailure(f"expected HTTP {expected_status}, got {status}")


def _check_marker(
    endpoint: Endpoint,
    marker: str,
    authorization: str,
    timeout: float,
    external_scheme: str | None = None,
) -> None:
    status, body = http_request(
        endpoint, "/", authorization=authorization, timeout=timeout, external_scheme=external_scheme
    )
    if status != 200:
        raise CheckFailure(f"expected HTTP 200, got {status}")
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise CheckFailure("application response was not valid JSON") from None
    if not isinstance(document, dict) or document.get("marker") != marker:
        raise CheckFailure("application JSON marker did not match")


def _record_check(name: str, operation: Callable[[], None], secrets_to_redact: tuple[str, ...]) -> dict:
    started = time.monotonic()
    row = {"name": name}
    try:
        operation()
        row["status"] = "passed"
    except Exception as error:
        row["status"] = "failed"
        row["error"] = sanitize_error(_safe_exception_message(error), secrets_to_redact)
    row["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
    return row


def run_endpoint_checks(
    endpoint: Endpoint,
    prefix: str,
    marker: str,
    user: str,
    password: str,
    timeout: float = DEFAULT_TIMEOUT,
    external_scheme: str | None = None,
) -> list[dict]:
    """Run HTTP and WebSocket checks, optionally marking a trusted loopback origin's scheme."""
    external_scheme = _validated_external_scheme(endpoint, external_scheme)
    auth = basic_authorization(user, password)
    redactions = (password, auth, auth.removeprefix("Basic "))
    checks = [
        _record_check(
            f"{prefix}_healthz",
            lambda: _check_http_status(
                endpoint, "/healthz", 200, authorization=None, timeout=timeout, external_scheme=external_scheme
            ),
            redactions,
        ),
        _record_check(
            f"{prefix}_readyz",
            lambda: _check_http_status(
                endpoint, "/readyz", 200, authorization=None, timeout=timeout, external_scheme=external_scheme
            ),
            redactions,
        ),
        _record_check(
            f"{prefix}_unauthenticated_401",
            lambda: _check_http_status(
                endpoint, "/", 401, authorization=None, timeout=timeout, external_scheme=external_scheme
            ),
            redactions,
        ),
        _record_check(
            f"{prefix}_authenticated_marker",
            lambda: _check_marker(endpoint, marker, auth, timeout, external_scheme=external_scheme),
            redactions,
        ),
        _record_check(
            f"{prefix}_websocket_echo",
            lambda: websocket_echo(
                endpoint, authorization=auth, timeout=timeout, external_scheme=external_scheme
            ),
            redactions,
        ),
    ]
    return checks


def run_probe(
    origin: str,
    public: str,
    marker: str,
    user: str,
    password: str,
    timeout: float = DEFAULT_TIMEOUT,
    external_scheme: str | None = None,
) -> dict:
    if not 0 < timeout <= 60:
        raise ValueError("timeout must be greater than 0 and at most 60 seconds")
    marker = validate_marker(marker)
    local_endpoint = validate_origin(origin)
    public_endpoint = validate_public(public)
    checks = run_endpoint_checks(
        local_endpoint, "origin", marker, user, password, timeout, external_scheme=external_scheme
    )
    checks.extend(run_endpoint_checks(public_endpoint, "public", marker, user, password, timeout))
    return {
        "origin": origin,
        "public": public,
        "checks": checks,
        "success": all(check["status"] == "passed" for check in checks),
    }

def write_report_exclusive(path: str, report: dict) -> None:
    with Path(path).open("x", encoding="utf-8") as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write("\n")


def _validate_fixture_host(host: str) -> str:
    if "%" in host:
        raise ValueError("fixture host must be a loopback IP literal")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("fixture host must be a loopback IP literal") from None
    if not address.is_loopback:
        raise ValueError("fixture must bind to loopback only")
    return str(address)


def create_fixture_server(marker: str, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    marker = validate_marker(marker)
    host = _validate_fixture_host(host)
    if not 0 <= port <= 65535:
        raise ValueError("fixture port must be between 0 and 65535")
    family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET

    class FixtureHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "TunnelAcceptanceFixture"
        sys_version = ""

        def log_message(self, _format: str, *args) -> None:
            return

        def parse_request(self) -> bool:
            if not super().parse_request():
                return False
            if self.headers.get_all("Authorization") is not None:
                self.close_connection = True
                self._send_json(401, {"error": "unauthorized"})
                return False
            return True


        def _send_json(self, status: int, document: dict) -> None:
            body = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_close(self, code: int) -> None:
            try:
                _send_ws_frame(self.wfile, 8, code.to_bytes(2, "big"))
            except OSError:
                pass

        def _websocket(self) -> None:
            upgrade = self.headers.get("Upgrade", "").strip().lower()
            connection_tokens = {
                item.strip().lower()
                for value in self.headers.get_all("Connection", [])
                for item in value.split(",")
            }
            version = self.headers.get("Sec-WebSocket-Version", "")
            key = self.headers.get("Sec-WebSocket-Key", "")
            try:
                decoded_key = base64.b64decode(key, validate=True)
            except (ValueError, base64.binascii.Error):
                decoded_key = b""
            if (
                upgrade != "websocket"
                or "upgrade" not in connection_tokens
                or version != "13"
                or len(decoded_key) != 16
            ):
                self._send_json(400, {"error": "invalid websocket handshake"})
                return
            accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()).decode("ascii")
            self.close_connection = True
            self.send_response_only(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            self.connection.settimeout(DEFAULT_TIMEOUT)
            while True:
                try:
                    frame = read_ws_frame(self.rfile, require_mask=True)
                except WebSocketProtocolError as error:
                    if str(error) == "unexpected end of WebSocket frame":
                        return
                    self._send_close(1002)
                    return
                except (OSError, TimeoutError):
                    return
                if not frame.fin:
                    self._send_close(1002)
                    return
                if frame.opcode == 9:
                    try:
                        _send_ws_frame(self.wfile, 10, frame.payload)
                    except OSError:
                        return
                    continue
                if frame.opcode == 8:
                    if len(frame.payload) == 1:
                        self._send_close(1002)
                    else:
                        try:
                            _send_ws_frame(self.wfile, 8, frame.payload)
                        except OSError:
                            pass
                    return
                if frame.opcode != 1:
                    self._send_close(1003)
                    return
                try:
                    frame.payload.decode("utf-8")
                except UnicodeDecodeError:
                    self._send_close(1007)
                    return
                try:
                    _send_ws_frame(self.wfile, 1, frame.payload)
                except OSError:
                    return

        def do_GET(self) -> None:
            route = urlsplit(self.path).path
            if route == "/socket":
                self._websocket()
            elif route == "/healthz":
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            else:
                self._send_json(200, {"marker": marker})

    class FixtureServer(ThreadingHTTPServer):
        address_family = family
        daemon_threads = True
        block_on_close = False
        allow_reuse_address = True

    return FixtureServer((host, port), FixtureHandler)


def run_fixture(host: str, port: int, marker: str) -> int:
    server = create_fixture_server(marker, host, port)
    serving = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    serving.start()
    old_handlers: dict[int, object] = {}
    stopping = False

    def stop_server(_signum, _frame) -> None:
        nonlocal stopping
        if not stopping:
            stopping = True
            server.shutdown()

    try:
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                old_handlers[sig] = signal.signal(sig, stop_server)
        bound_host, bound_port = server.server_address[:2]
        rendered_host = f"[{bound_host}]" if ":" in bound_host else bound_host
        print(f"http://{rendered_host}:{bound_port}", flush=True)
        serving.join()
    except KeyboardInterrupt:
        stop_server(signal.SIGINT, None)
    finally:
        if serving.is_alive():
            server.shutdown()
            serving.join()
        server.server_close()
        for sig, old_handler in old_handlers.items():
            signal.signal(sig, old_handler)
    return 0


class _UsageParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: invalid arguments\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _UsageParser(description="Local tunnel fixture and HTTP/WS acceptance probe")
    commands = parser.add_subparsers(dest="command", required=True)
    fixture = commands.add_parser("fixture", help="serve a loopback-only HTTP and WebSocket fixture")
    fixture.add_argument("--host", default="127.0.0.1", help="loopback IP to bind (default: 127.0.0.1)")
    fixture.add_argument("--port", type=int, default=0, help="port to bind (default: ephemeral)")
    fixture.add_argument("--marker", required=True, help="nonsecret JSON marker returned by the fixture")
    probe = commands.add_parser("probe", help="check local and public HTTP authentication and WS/WSS")
    probe.add_argument("--origin", default="http://127.0.0.1:8081", help="local HTTP loopback origin")
    probe.add_argument("--public", default="https://omni.curl.rs", help="public HTTPS origin")
    probe.add_argument("--marker", required=True, help="expected nonsecret JSON marker")
    probe.add_argument("--user", default="admin", help="Basic authentication username")
    probe.add_argument(
        "--password-env",
        default="WEB_HTTP_AUTH_PASSWORD",
        help="environment variable holding the Basic authentication password",
    )
    probe.add_argument(
        "--origin-external-scheme",
        choices=("http", "https"),
        default=None,
        help="trusted external scheme for loopback HTTP origin checks only",
    )
    probe.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-connection timeout, up to 60s")
    probe.add_argument("--output", required=True, help="new JSON report path; existing files are never overwritten")
    return parser


def _run_probe_cli(args: argparse.Namespace) -> int:
    if not 0 < args.timeout <= 60:
        raise ValueError("timeout must be greater than 0 and at most 60 seconds")
    password = os.environ.get(args.password_env)
    if password is None:
        raise ValueError("password environment variable is not set")
    report = run_probe(
        args.origin,
        args.public,
        args.marker,
        args.user,
        password,
        args.timeout,
        external_scheme=args.origin_external_scheme,
    )
    write_report_exclusive(args.output, report)
    failed = [check["name"] for check in report["checks"] if check["status"] != "passed"]
    if failed:
        print(f"Probe failed {len(failed)}/{len(report['checks'])} checks: {', '.join(failed)}")
        return 1
    print(f"Probe passed all {len(report['checks'])} checks; report saved.")
    return 0

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "fixture":
            return run_fixture(args.host, args.port, args.marker)
        return _run_probe_cli(args)
    except ValueError:
        print("tunnel acceptance failed: invalid configuration", file=sys.stderr)
        return 1
    except OSError:
        print("tunnel acceptance failed: could not bind fixture or create report", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
