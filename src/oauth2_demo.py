#!/usr/bin/env python3
"""
OAuth 2.0 Demo
Demonstrates OAuth 2.0 authorization flows — the protocol behind
"Login with Google", API access delegation, and service-to-service auth.
"""

import base64
import hashlib
import json
import secrets
import time
from datetime import datetime, timezone, timedelta


def generate_access_token(client_id, scopes, subject=None, token_type="Bearer"):
    now = int(time.time())
    expires_in = 3600

    token_payload = {
        "iss": "https://auth.wellsfargo.com",
        "sub": subject or client_id,
        "aud": "https://api.wellsfargo.com",
        "iat": now,
        "exp": now + expires_in,
        "jti": secrets.token_hex(16),
        "client_id": client_id,
        "scope": " ".join(scopes),
        "token_type": token_type
    }

    header = base64.b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).decode().rstrip("=")

    payload = base64.b64encode(
        json.dumps(token_payload).encode()
    ).decode().rstrip("=")

    signature = hashlib.sha256(f"{header}.{payload}".encode()).hexdigest()[:32]
    token = f"{header}.{payload}.{signature}"

    return token, token_payload, expires_in


def generate_authorization_code(user_id, client_id, scopes, redirect_uri):
    code = secrets.token_urlsafe(32)
    return {
        "code": code,
        "user_id": user_id,
        "client_id": client_id,
        "scopes": scopes,
        "redirect_uri": redirect_uri,
        "expires_at": int(time.time()) + 600,
        "used": False
    }


def validate_token(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False, "Invalid token format"

        payload = json.loads(base64.b64decode(parts[1] + "==").decode())
        now = int(time.time())

        if payload.get("exp", 0) < now:
            return False, f"Token expired at {datetime.fromtimestamp(payload['exp'])}"

        return True, payload
    except Exception as e:
        return False, str(e)


def run():
    print("\n" + "=" * 60)
    print(" OAuth 2.0 DEMO — Authorization Framework")
    print("=" * 60 + "\n")

    print("[Flow 1] Authorization Code Flow (Web Applications)")
    print("-" * 40)
    print("  Used for: Web apps where user logs in interactively")
    print("  Example: Employee accessing internal API via web portal")
    print()

    print("  Step 1: User clicks 'Login' — browser redirects to IdP")
    print("  GET https://auth.wellsfargo.com/authorize?")
    print("      response_type=code")
    print("      &client_id=splunk-dashboard")
    print("      &redirect_uri=https://splunk.wellsfargo.com/callback")
    print("      &scope=read:logs write:alerts")
    print("      &state=abc123xyz")
    print()

    print("  Step 2: User authenticates, IdP generates auth code")
    auth_code = generate_authorization_code(
        user_id="idris.junaid@wellsfargo.com",
        client_id="splunk-dashboard",
        scopes=["read:logs", "write:alerts"],
        redirect_uri="https://splunk.wellsfargo.com/callback"
    )
    print(f"  Auth Code: {auth_code['code'][:20]}...")
    print(f"  Expires:   10 minutes")
    print(f"  Single use: True")
    print()

    print("  Step 3: App exchanges code for access token")
    token, payload, expires_in = generate_access_token(
        client_id="splunk-dashboard",
        scopes=["read:logs", "write:alerts"],
        subject="idris.junaid@wellsfargo.com"
    )
    print(f"  Access Token: {token[:60]}...")
    print(f"  Expires in:   {expires_in} seconds (1 hour)")
    print(f"  Scopes:       {payload['scope']}")
    print()

    print("  Step 4: App calls API with token")
    print("  GET https://api.wellsfargo.com/v1/security/logs")
    print("  Authorization: Bearer <access_token>")
    print()

    valid, result = validate_token(token)
    print(f"  Token validation: {'✓ VALID' if valid else '✗ INVALID'}")
    if valid:
        print(f"  Subject: {result.get('sub')}")
        print(f"  Scopes:  {result.get('scope')}")
    print()

    print("[Flow 2] Client Credentials Flow (Service-to-Service)")
    print("-" * 40)
    print("  Used for: Automated services, no user interaction")
    print("  Example: SOAR automation calling security API")
    print()

    svc_token, svc_payload, _ = generate_access_token(
        client_id="soar-automation-service",
        scopes=["read:alerts", "write:incidents", "execute:playbooks"],
        token_type="Bearer"
    )
    print(f"  Service: soar-automation-service")
    print(f"  Token:   {svc_token[:60]}...")
    print(f"  Scopes:  {svc_payload['scope']}")
    print(f"  Note:    No user involved — machine-to-machine auth")
    print()

    print("[Security Considerations]")
    print("-" * 40)
    print("  ✓ Tokens are short-lived (1 hour)")
    print("  ✓ Scopes limit what the token can do")
    print("  ✓ Authorization codes are single-use")
    print("  ✓ State parameter prevents CSRF attacks")
    print("  ✗ Never store tokens in localStorage (XSS risk)")
    print("  ✗ Never put tokens in URLs (logged by servers)")
    print()

    print("=" * 60)
    print(" OAuth 2.0 Key Concepts:")
    print("  - Authorization Server = issues tokens (Okta, Azure AD)")
    print("  - Resource Server = API being protected")
    print("  - Client = app requesting access")
    print("  - Scope = what the token allows")
    print("  - Grant Type = which OAuth flow to use")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run()
