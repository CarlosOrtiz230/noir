"""Mock ZAP-format alert data for the Noir Security Scanner UI."""


ALERTS = [
    # ── High (10) ─────────────────────────────────────────────────────────
    {
        "id": 1, "alert": "SQL Injection", "risk": "High",
        "confidence": "Confirmed",
        "url": "/api/users", "method": "GET",
        "param": "search", "attack": "admin' OR '1'='1' --",
        "description": (
            "The search query parameter is directly interpolated into a SQL "
            "query without parameterized statements, allowing extraction of "
            "the entire database or data modification."
        ),
        "evidence": (
            "GET /api/users?search=admin' OR '1'='1' --\n"
            "HTTP/1.1 200 OK\n"
            '{"users":[{"id":1,"username":"admin","role":"superadmin"}]}'
        ),
        "solution": (
            "Use parameterized queries or prepared statements. "
            "Apply strict input validation on the search parameter. "
            "Enforce least-privilege database accounts."
        ),
        "reference": "https://cwe.mitre.org/data/definitions/89.html",
        "cweid": "89", "wascid": "19",
    },
    {
        "id": 2, "alert": "Remote Code Execution - Deserialization",
        "risk": "High", "confidence": "High",
        "url": "/api/data/import", "method": "POST",
        "param": "body", "attack": "[crafted serialized payload]",
        "description": (
            "The import endpoint deserializes user-supplied data using an "
            "unsafe module without integrity checks, allowing arbitrary code "
            "execution on the server."
        ),
        "evidence": (
            "POST /api/data/import\nContent-Type: application/octet-stream\n\n"
            "[crafted payload]\nServer executed: uid=1000(app)"
        ),
        "solution": (
            "Replace unsafe deserialization with JSON. Use cryptographic "
            "signing for binary formats. Sandbox the import service."
        ),
        "reference": "https://cwe.mitre.org/data/definitions/502.html",
        "cweid": "502", "wascid": "20",
    },
    {
        "id": 3, "alert": "Authentication Bypass - JWT None Algorithm",
        "risk": "High", "confidence": "Confirmed",
        "url": "/api/auth/login", "method": "POST",
        "param": "alg", "attack": '{"alg":"none","typ":"JWT"}',
        "description": (
            "JWT validation accepts tokens with alg:none, allowing any user "
            "to forge valid authentication tokens and bypass all access controls."
        ),
        "evidence": (
            'Header: {"alg":"none","typ":"JWT"}\n'
            'Payload: {"sub":"admin","role":"superadmin"}\n'
            "Signature: (empty)\nResponse: 200 OK - admin access granted"
        ),
        "solution": (
            "Explicitly reject the 'none' algorithm. Pin the expected "
            "algorithm (e.g. RS256) server-side. Validate all JWT claims."
        ),
        "reference": "https://cwe.mitre.org/data/definitions/345.html",
        "cweid": "345", "wascid": "13",
    },
    {
        "id": 4, "alert": "IDOR - User Profile Access", "risk": "High",
        "confidence": "High",
        "url": "/api/users/{id}/profile", "method": "GET",
        "param": "id", "attack": "/api/users/999/profile",
        "description": (
            "Any authenticated user can access other users' profiles by "
            "changing the ID parameter in the URL."
        ),
        "evidence": "GET /api/users/999/profile (as user id=1) -> 200 OK with user 999 PII",
        "solution": "Verify the requesting user owns the resource or has admin privileges.",
        "reference": "https://cwe.mitre.org/data/definitions/639.html",
        "cweid": "639", "wascid": "2",
    },
    {
        "id": 5, "alert": "Mass Assignment", "risk": "High",
        "confidence": "High",
        "url": "/api/auth/register", "method": "POST",
        "param": "role", "attack": '{"username":"evil","password":"pw","role":"admin"}',
        "description": (
            "The registration endpoint binds all request body fields, "
            "allowing users to set their own role to 'admin'."
        ),
        "evidence": 'POST /api/auth/register {"role":"admin"} -> 201 Created with admin role',
        "solution": "Whitelist allowed fields during registration. Never bind role fields from user input.",
        "reference": "https://cwe.mitre.org/data/definitions/915.html",
        "cweid": "915", "wascid": "20",
    },
    {
        "id": 6, "alert": "Server-Side Request Forgery", "risk": "High",
        "confidence": "Confirmed",
        "url": "/api/webhooks", "method": "POST",
        "param": "url", "attack": "http://169.254.169.254/latest/meta-data/",
        "description": (
            "The webhook URL field is not validated, allowing requests to "
            "internal services and cloud metadata endpoints."
        ),
        "evidence": (
            'POST /api/webhooks {"url":"http://169.254.169.254/latest/meta-data/"}\n'
            "-> 200 OK with cloud credentials"
        ),
        "solution": "Validate and restrict webhook URLs to allowed domains. Block private IP ranges.",
        "reference": "https://cwe.mitre.org/data/definitions/918.html",
        "cweid": "918", "wascid": "15",
    },
    {
        "id": 7, "alert": "Weak JWT Signing Key", "risk": "High",
        "confidence": "High",
        "url": "/api/auth/*", "method": "*",
        "param": "", "attack": "hashcat dictionary attack",
        "description": "The JWT secret key is a common dictionary word and can be brute-forced in seconds.",
        "evidence": "Cracked JWT secret using hashcat in 0.3s: secret = 'secret123'",
        "solution": "Use a cryptographically random secret of at least 256 bits. Consider RS256.",
        "reference": "https://cwe.mitre.org/data/definitions/326.html",
        "cweid": "326", "wascid": "13",
    },
    {
        "id": 8, "alert": "XML External Entity Injection", "risk": "High",
        "confidence": "High",
        "url": "/api/data/import", "method": "POST",
        "param": "body", "attack": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
        "description": "XML input is parsed with external entity resolution enabled, allowing local file reads.",
        "evidence": "XXE payload -> server returned contents of /etc/passwd",
        "solution": "Disable DTD processing and external entity resolution in the XML parser.",
        "reference": "https://cwe.mitre.org/data/definitions/611.html",
        "cweid": "611", "wascid": "43",
    },
    {
        "id": 9, "alert": "IDOR - Sequential Document IDs", "risk": "High",
        "confidence": "High",
        "url": "/api/documents/{id}", "method": "GET",
        "param": "id", "attack": "enumeration 1..500",
        "description": "Document IDs are sequential integers. Any authenticated user can enumerate and access all documents.",
        "evidence": "GET /api/documents/1 through /500 -> all 200 OK with contents",
        "solution": "Use UUIDs for document identifiers. Implement ownership checks on every access.",
        "reference": "https://cwe.mitre.org/data/definitions/639.html",
        "cweid": "639", "wascid": "2",
    },
    {
        "id": 10, "alert": "Privilege Escalation via Role Update",
        "risk": "High", "confidence": "Confirmed",
        "url": "/api/admin/users/{id}/role", "method": "PUT",
        "param": "role", "attack": '{"role":"admin"}',
        "description": "The role update endpoint does not verify that the caller is an admin.",
        "evidence": 'PUT /api/admin/users/1/role {"role":"admin"} (as regular user) -> 200 OK',
        "solution": "Enforce role-based access control. Only superadmins should modify user roles.",
        "reference": "https://cwe.mitre.org/data/definitions/269.html",
        "cweid": "269", "wascid": "2",
    },
    # ── Medium (10) ───────────────────────────────────────────────────────
    {
        "id": 11, "alert": "Cross Site Scripting (Stored)", "risk": "Medium",
        "confidence": "High",
        "url": "/api/comments", "method": "POST",
        "param": "body", "attack": "<script>alert(1)</script>",
        "description": "Comment content is rendered without sanitization, allowing script injection.",
        "evidence": "POST /api/comments with <script> -> stored and rendered to other users",
        "solution": "Sanitize all user-generated HTML. Use a Content Security Policy.",
        "reference": "https://cwe.mitre.org/data/definitions/79.html",
        "cweid": "79", "wascid": "8",
    },
    {
        "id": 12, "alert": "CORS Misconfiguration", "risk": "Medium",
        "confidence": "High",
        "url": "/api/*", "method": "*",
        "param": "", "attack": "",
        "description": "Access-Control-Allow-Origin is set to '*' with credentials allowed.",
        "evidence": "Access-Control-Allow-Origin: * / Access-Control-Allow-Credentials: true",
        "solution": "Set explicit allowed origins. Never combine wildcard origin with credentials.",
        "reference": "https://cwe.mitre.org/data/definitions/942.html",
        "cweid": "942", "wascid": "14",
    },
    {
        "id": 13, "alert": "Insufficient Rate Limiting", "risk": "Medium",
        "confidence": "Medium",
        "url": "/api/auth/login", "method": "POST",
        "param": "", "attack": "10,000 login attempts in 60s",
        "description": "No rate limiting on login attempts allows brute-force password attacks.",
        "evidence": "Sent 10,000 login attempts in 60 seconds — no throttling triggered",
        "solution": "Implement progressive rate limiting (5 attempts/min). Add account lockout.",
        "reference": "https://cwe.mitre.org/data/definitions/307.html",
        "cweid": "307", "wascid": "11",
    },
    {
        "id": 14, "alert": "Information Disclosure - PII in Error Response",
        "risk": "Medium", "confidence": "High",
        "url": "/api/users/{id}", "method": "GET",
        "param": "id", "attack": "invalid",
        "description": "Error responses for invalid user IDs include internal user data and email addresses.",
        "evidence": 'GET /api/users/invalid -> 400 {"error":"User not found","context":{"email":"user@corp.com"}}',
        "solution": "Return generic error messages. Never include internal data in error responses.",
        "reference": "https://cwe.mitre.org/data/definitions/209.html",
        "cweid": "209", "wascid": "13",
    },
    {
        "id": 15, "alert": "Content Security Policy Header Not Set",
        "risk": "Medium", "confidence": "High",
        "url": "/", "method": "GET",
        "param": "", "attack": "",
        "description": "Responses lack Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options.",
        "evidence": "Missing: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy",
        "solution": "Add all recommended security headers. Use a security middleware.",
        "reference": "https://cwe.mitre.org/data/definitions/693.html",
        "cweid": "693", "wascid": "15",
    },
    {
        "id": 16, "alert": "Information Disclosure - Debug Error Messages",
        "risk": "Medium", "confidence": "Medium",
        "url": "/api/*", "method": "*",
        "param": "", "attack": "",
        "description": "Unhandled exceptions return full stack traces revealing file paths and library versions.",
        "evidence": "500 response includes internal file paths and line numbers",
        "solution": "Disable debug mode in production. Implement a global exception handler.",
        "reference": "https://cwe.mitre.org/data/definitions/209.html",
        "cweid": "209", "wascid": "13",
    },
    {
        "id": 17, "alert": "Unrestricted File Upload", "risk": "Medium",
        "confidence": "High",
        "url": "/api/files/upload", "method": "POST",
        "param": "file", "attack": "malicious.php",
        "description": "The upload endpoint accepts any file type including executable formats.",
        "evidence": "POST malicious.php -> 201 Created, accessible at /uploads/malicious.php",
        "solution": "Whitelist allowed file extensions and MIME types. Store uploads outside the web root.",
        "reference": "https://cwe.mitre.org/data/definitions/434.html",
        "cweid": "434", "wascid": "34",
    },
    {
        "id": 18, "alert": "HTTP Parameter Pollution", "risk": "Medium",
        "confidence": "Medium",
        "url": "/api/users", "method": "GET",
        "param": "role", "attack": "?role=user&role=admin",
        "description": "Duplicate query parameters cause inconsistent behavior between validation and backend.",
        "evidence": "GET /api/users?role=user&role=admin -> validation checks 'user', backend uses 'admin'",
        "solution": "Use strict parameter parsing. Reject requests with duplicate parameters.",
        "reference": "https://cwe.mitre.org/data/definitions/235.html",
        "cweid": "235", "wascid": "8",
    },
    {
        "id": 19, "alert": "Open Redirect", "risk": "Medium",
        "confidence": "High",
        "url": "/api/auth/callback", "method": "GET",
        "param": "redirect_uri", "attack": "https://evil.example.com",
        "description": "The redirect_uri parameter is not validated, allowing redirection to malicious sites.",
        "evidence": "GET /api/auth/callback?redirect_uri=https://evil.example.com -> 302",
        "solution": "Whitelist allowed redirect URIs. Validate against registered callback URLs.",
        "reference": "https://cwe.mitre.org/data/definitions/601.html",
        "cweid": "601", "wascid": "38",
    },
    {
        "id": 20, "alert": "Session Fixation", "risk": "Medium",
        "confidence": "High",
        "url": "/api/auth/login", "method": "POST",
        "param": "", "attack": "",
        "description": "Session ID is not regenerated after login, allowing session fixation.",
        "evidence": "Pre-login session ID equals post-login session ID: sess=abc123",
        "solution": "Regenerate the session ID upon successful authentication.",
        "reference": "https://cwe.mitre.org/data/definitions/384.html",
        "cweid": "384", "wascid": "37",
    },
    # ── Low (7) ───────────────────────────────────────────────────────────
    {
        "id": 21, "alert": "Server Leaks Version Information", "risk": "Low",
        "confidence": "High",
        "url": "/", "method": "GET",
        "param": "", "attack": "",
        "description": "The Server header reveals the exact software version used.",
        "evidence": "Server: nginx/1.21.6, X-Powered-By: Express 4.18.2",
        "solution": "Remove or obfuscate the Server and X-Powered-By headers.",
        "reference": "https://cwe.mitre.org/data/definitions/200.html",
        "cweid": "200", "wascid": "13",
    },
    {
        "id": 22, "alert": "Cookie Without Secure Flag", "risk": "Low",
        "confidence": "Medium",
        "url": "/api/auth/login", "method": "POST",
        "param": "", "attack": "",
        "description": "Session cookie is set without the Secure flag.",
        "evidence": "Set-Cookie: session=abc123; HttpOnly; Path=/ (missing Secure, SameSite)",
        "solution": "Add Secure and SameSite=Strict flags to all session cookies.",
        "reference": "https://cwe.mitre.org/data/definitions/614.html",
        "cweid": "614", "wascid": "13",
    },
    {
        "id": 23, "alert": "Content-Type Header Missing", "risk": "Low",
        "confidence": "Medium",
        "url": "/api/data/import", "method": "POST",
        "param": "", "attack": "",
        "description": "The endpoint processes requests regardless of Content-Type header value.",
        "evidence": "POST with Content-Type: text/plain accepted and processed as JSON",
        "solution": "Validate Content-Type header matches expected format. Reject unexpected types.",
        "reference": "https://cwe.mitre.org/data/definitions/20.html",
        "cweid": "20", "wascid": "20",
    },
    {
        "id": 24, "alert": "Information Disclosure - API Version Headers",
        "risk": "Low", "confidence": "Medium",
        "url": "/api/*", "method": "GET",
        "param": "", "attack": "",
        "description": "API version and build number are returned in response headers.",
        "evidence": "X-API-Version: 2.4.1-beta, X-Build: 20250110-a1b2c3d",
        "solution": "Remove version and build headers from production responses.",
        "reference": "https://cwe.mitre.org/data/definitions/200.html",
        "cweid": "200", "wascid": "13",
    },
    {
        "id": 25, "alert": "Deprecated TLS Version Supported", "risk": "Low",
        "confidence": "High",
        "url": "*", "method": "*",
        "param": "", "attack": "",
        "description": "Server accepts TLS 1.0 connections which have known cryptographic weaknesses.",
        "evidence": "TLS handshake successful with TLS 1.0 (should only allow TLS 1.2+)",
        "solution": "Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and above.",
        "reference": "https://cwe.mitre.org/data/definitions/327.html",
        "cweid": "327", "wascid": "4",
    },
    {
        "id": 26, "alert": "Absence of Rate Limiting", "risk": "Low",
        "confidence": "Medium",
        "url": "/api/documents", "method": "GET",
        "param": "limit", "attack": "?limit=999999",
        "description": "Public document listing has no pagination limits or request throttling.",
        "evidence": "GET /api/documents?limit=999999 -> returns all 50,000 documents",
        "solution": "Enforce maximum page size. Implement request rate limiting.",
        "reference": "https://cwe.mitre.org/data/definitions/799.html",
        "cweid": "799", "wascid": "11",
    },
    {
        "id": 27, "alert": "Strict-Transport-Security Header Not Set",
        "risk": "Low", "confidence": "High",
        "url": "/", "method": "GET",
        "param": "", "attack": "",
        "description": "HSTS header is not set, allowing protocol downgrade attacks.",
        "evidence": "Response lacks Strict-Transport-Security header",
        "solution": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "reference": "https://cwe.mitre.org/data/definitions/319.html",
        "cweid": "319", "wascid": "15",
    },
    # ── Informational (3) ─────────────────────────────────────────────────
    {
        "id": 28, "alert": "Server Technology Fingerprinted", "risk": "Informational",
        "confidence": "Medium",
        "url": "/", "method": "GET",
        "param": "", "attack": "",
        "description": "Multiple headers and response patterns reveal the underlying technology stack.",
        "evidence": "Detected: Python 3.11, FastAPI 0.104, Uvicorn, PostgreSQL",
        "solution": "Minimize information leakage through headers and error messages.",
        "reference": "https://cwe.mitre.org/data/definitions/200.html",
        "cweid": "200", "wascid": "13",
    },
    {
        "id": 29, "alert": "Information Disclosure - API Documentation",
        "risk": "Informational", "confidence": "High",
        "url": "/api/docs", "method": "GET",
        "param": "", "attack": "",
        "description": "Swagger/OpenAPI documentation is accessible without authentication.",
        "evidence": "GET /api/docs -> 200 OK with full API specification",
        "solution": "Restrict API documentation access to authenticated internal users.",
        "reference": "https://cwe.mitre.org/data/definitions/200.html",
        "cweid": "200", "wascid": "13",
    },
    {
        "id": 30, "alert": "OPTIONS Method Enabled", "risk": "Informational",
        "confidence": "Low",
        "url": "/api/*", "method": "OPTIONS",
        "param": "", "attack": "",
        "description": "All endpoints respond to OPTIONS requests, potentially aiding reconnaissance.",
        "evidence": "OPTIONS /api/admin/users -> 200 OK, Allow: GET, PUT, DELETE, OPTIONS",
        "solution": "Restrict OPTIONS responses to endpoints that require CORS preflight.",
        "reference": "https://cwe.mitre.org/data/definitions/200.html",
        "cweid": "200", "wascid": "13",
    },
]

ENDPOINTS = {
    "/api/auth": [
        {"method": "POST", "path": "/api/auth/login", "tested": True, "vulns": 4},
        {"method": "POST", "path": "/api/auth/register", "tested": True, "vulns": 1},
        {"method": "POST", "path": "/api/auth/logout", "tested": True, "vulns": 0},
        {"method": "GET", "path": "/api/auth/refresh", "tested": True, "vulns": 0},
    ],
    "/api/users": [
        {"method": "GET", "path": "/api/users", "tested": True, "vulns": 3},
        {"method": "GET", "path": "/api/users/{id}", "tested": True, "vulns": 1},
        {"method": "PUT", "path": "/api/users/{id}", "tested": True, "vulns": 0},
        {"method": "DELETE", "path": "/api/users/{id}", "tested": False, "vulns": 0},
        {"method": "GET", "path": "/api/users/{id}/profile", "tested": True, "vulns": 1},
    ],
    "/api/documents": [
        {"method": "GET", "path": "/api/documents", "tested": True, "vulns": 1},
        {"method": "POST", "path": "/api/documents", "tested": True, "vulns": 0},
        {"method": "GET", "path": "/api/documents/{id}", "tested": True, "vulns": 1},
        {"method": "PUT", "path": "/api/documents/{id}", "tested": False, "vulns": 0},
        {"method": "DELETE", "path": "/api/documents/{id}", "tested": False, "vulns": 0},
    ],
    "/api/admin": [
        {"method": "GET", "path": "/api/admin/users", "tested": True, "vulns": 0},
        {"method": "PUT", "path": "/api/admin/users/{id}/role", "tested": True, "vulns": 1},
        {"method": "GET", "path": "/api/admin/settings", "tested": True, "vulns": 0},
        {"method": "PUT", "path": "/api/admin/settings", "tested": False, "vulns": 0},
    ],
    "/api/webhooks": [
        {"method": "POST", "path": "/api/webhooks", "tested": True, "vulns": 1},
    ],
    "/api/data": [
        {"method": "POST", "path": "/api/data/import", "tested": True, "vulns": 3},
    ],
}

SCAN_HISTORY = [
    {
        "id": "scan-001",
        "name": "Full API Scan",
        "target": "https://api.example.com",
        "scan_type": "Full Scan",
        "date": "2025-01-15 14:30",
        "duration": "12m 34s",
        "total": 30, "high": 10, "medium": 10, "low": 7, "informational": 3,
        "endpoints_tested": 16, "endpoints_total": 20,
    },
    {
        "id": "scan-002",
        "name": "Staging Quick Scan",
        "target": "https://staging.example.com/api",
        "scan_type": "Quick Scan",
        "date": "2025-01-10 09:15",
        "duration": "3m 22s",
        "total": 12, "high": 4, "medium": 5, "low": 2, "informational": 1,
        "endpoints_tested": 10, "endpoints_total": 20,
    },
    {
        "id": "scan-003",
        "name": "Auth Endpoints Only",
        "target": "https://api.example.com/auth",
        "scan_type": "Authentication",
        "date": "2025-01-05 16:45",
        "duration": "2m 10s",
        "total": 5, "high": 3, "medium": 1, "low": 1, "informational": 0,
        "endpoints_tested": 4, "endpoints_total": 4,
    },
    {
        "id": "scan-004",
        "name": "OWASP Top 10 Check",
        "target": "https://api.example.com",
        "scan_type": "OWASP Top 10",
        "date": "2024-12-28 11:00",
        "duration": "8m 55s",
        "total": 18, "high": 7, "medium": 7, "low": 3, "informational": 1,
        "endpoints_tested": 14, "endpoints_total": 20,
    },
]

RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}

SCAN_ACTIVITY_MESSAGES = [
    "Initializing scanner…",
    "Parsing OpenAPI specification…",
    "Spidering target…",
    "Discovering API endpoints…",
    "Testing authentication mechanisms…",
    "Active scanning /api/auth/login…",
    "Active scanning /api/users…",
    "Active scanning /api/documents…",
    "Active scanning /api/webhooks…",
    "Active scanning /api/admin…",
    "Running OWASP Top 10 policy…",
    "Analyzing response patterns…",
    "Checking security headers…",
    "Testing rate limiting…",
    "Validating CORS configuration…",
    "Generating alerts…",
]
