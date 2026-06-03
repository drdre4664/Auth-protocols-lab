#!/usr/bin/env python3
"""
OpenID Connect (OIDC) Demo
OIDC adds an identity layer on top of OAuth 2.0.
While OAuth answers "what can this app do?", OIDC answers "who is this user?"
"""

import base64
import hashlib
import json
import secrets
import time
from datetime import datetime, timezone


def generate_id_token(
    user_email,
    user_name,
    roles,
    client_id,
    issuer="https://auth.wellsfargo.com",
    auth_method="password"
):
    now = int(time.time())
    nonce = secrets.token_hex(16)

    id_token_payload = {
        "iss": issuer,
        "sub": hashlib.sha256(user_email.encode()).hexdigest()[:32],
        "aud": client_id,
        "iat": now,
        "exp": now + 3600,
        "nonce": nonce,
        "email": user_email,
        "email_verified": True,
        "name": user_name,
        "given_name": user_name.split()[0],
        "family_name": user_name.split()[-1],
        "preferred_username": user_email.split("@")[0],
        "groups": roles,
        "department": "Cybersecurity",
        "amr": [auth_method, "mfa"],
        "acr": "urn:mace:incommon:iap:silver",
        "auth_time": now,
        "at_hash": secrets.token_hex(16)[:22],
        "employee_id": "WF-" + secrets.token_hex(4).upper(),
        "cost_center": "CC-CYBERSEC-001"
    }

    header = base64.b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT", "kid": "wellsfargo-key-2026"}).encode()
    ).decode().rstrip("=")

    payload_b64 = base64.b64encode(
        json.dumps(id_token_payload).encode()
    ).decode().rstrip("=")

    signature = hashlib.sha256(f"{header}.{payload_b64}".encode()).hexdigest()[:43]
    id_token = f"{header}.{payload_b64}.{signature}"

    return id_token, id_token_payload, nonce


def decode_id_token(id_token):
    parts = id_token.split(".")
    if len(parts) != 3:
        return None, "Invalid JWT format"
    try:
        padding = 4 - len(parts[1]) % 4
        payload = json.loads(base64.b64decode(parts[1] + "=" * padding).decode())
        return payload, None
    except Exception as e:
        return None, str(e)


def validate_id_token(id_token_payload, expected_client_id, expected_issuer):
    issues = []
    now = int(time.time())

    if id_token_payload.get("iss") == expected_issuer:
        issues.append(f"PASS: Issuer verified — {expected_issuer}")
    else:
        issues.append(f"FAIL: Issuer mismatch")

    if id_token_payload.get("aud") == expected_client_id:
        issues.append(f"PASS: Audience verified — {expected_client_id}")
    else:
        issues.append(f"FAIL: Token not intended for this client")

    if id_token_payload.get("exp", 0) > now:
        remaining = id_token_payload["exp"] - now
        issues.append(f"PASS: Token valid for {remaining} more seconds")
    else:
        issues.append("FAIL: Token has expired")

    if id_token_payload.get("email_verified"):
        issues.append(f"PASS: Email verified — {id_token_payload.get('email')}")
    else:
        issues.append("WARN: Email not verified")

    amr = id_token_payload.get("amr", [])
    if "mfa" in amr:
        issues.append(f"PASS: MFA confirmed — methods: {amr}")
    else:
        issues.append("WARN: MFA not confirmed in token")

    return issues


def run():
    print("\n" + "=" * 60)
    print(" OpenID Connect (OIDC) DEMO — Identity Layer")
    print("=" * 60 + "\n")

    print("[Concept] OAuth 2.0 vs OpenID Connect")
    print("-" * 40)
    print("  OAuth 2.0:  'This app can read your files' (authorization)")
    print("  OIDC:       'This is John Smith, john@wf.com' (authentication)")
    print("  OIDC adds:  ID Token (JWT with user identity claims)")
    print()

    print("[1] User authenticates — IdP issues ID Token + Access Token")
    print("-" * 40)

    id_token, payload, nonce = generate_id_token(
        user_email="idris.junaid@wellsfargo.com",
        user_name="Idris Junaid",
        roles=["SecurityAnalyst", "CTFCMember", "SIEMUser"],
        client_id="security-portal",
        auth_method="password"
    )

    print(f"  ID Token (JWT): {id_token[:80]}...")
    print()

    print("[2] Decoded ID Token Claims")
    print("-" * 40)
    decoded, err = decode_id_token(id_token)
    if decoded:
        important_claims = [
            "sub", "email", "name", "groups",
            "department", "amr", "employee_id", "exp"
        ]
        for claim in important_claims:
            if claim in decoded:
                value = decoded[claim]
                if claim == "exp":
                    value = f"{value} ({datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')})"
                print(f"  {claim:<20}: {value}")
    print()

    print("[3] Application validates ID Token")
    print("-" * 40)
    validation = validate_id_token(
        payload,
        expected_client_id="security-portal",
        expected_issuer="https://auth.wellsfargo.com"
    )
    for result in validation:
        icon = "✓" if "PASS" in result else "✗" if "FAIL" in result else "⚠"
        print(f"  {icon} {result}")
    print()

    print("[4] UserInfo Endpoint (additional claims)")
    print("-" * 40)
    userinfo = {
        "sub": payload["sub"],
        "email": payload["email"],
        "name": payload["name"],
        "groups": payload["groups"],
        "department": payload["department"],
        "cost_center": payload["cost_center"],
        "employee_id": payload["employee_id"],
        "manager": "manager@wellsfargo.com",
        "location": "Charlotte, NC"
    }
    print(json.dumps(userinfo, indent=2))
    print()

    print("[5] OIDC vs SAML Comparison")
    print("-" * 40)
    print("  SAML:  XML-based, older, enterprise B2B federation")
    print("  OIDC:  JSON/JWT-based, modern, mobile-friendly")
    print("  Both:  Achieve SSO — choice depends on SP support")
    print("  WF:    Uses both — SAML for legacy apps, OIDC for modern")
    print()

    print("=" * 60)
    print(" OIDC Key Claims:")
    print("  sub   = unique user identifier (never changes)")
    print("  iss   = who issued the token")
    print("  aud   = who the token is for")
    print("  exp   = when token expires")
    print("  amr   = authentication methods used (pwd, mfa, etc)")
    print("  email = user's email (requires 'email' scope)")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run()
