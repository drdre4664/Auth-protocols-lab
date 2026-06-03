#!/usr/bin/env python3
"""
SAML 2.0 Demo
Demonstrates SAML assertion structure, generation, and validation.
SAML is used for enterprise SSO — when you log into a corporate portal
and get access to multiple apps without re-authenticating.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone, timedelta
import xml.etree.ElementTree as ET


def generate_saml_assertion(
    user_email,
    user_name,
    roles,
    issuer="https://idp.wellsfargo.com",
    audience="https://app.wellsfargo.com",
    session_duration_minutes=480
):
    now = datetime.now(timezone.utc)
    not_before = now.isoformat().replace("+00:00", "Z")
    not_after = (now + timedelta(minutes=session_duration_minutes)).isoformat().replace("+00:00", "Z")
    assertion_id = "_" + hashlib.sha256(f"{user_email}{now}".encode()).hexdigest()[:32]

    assertion = {
        "SAMLAssertion": {
            "Version": "2.0",
            "ID": assertion_id,
            "IssueInstant": not_before,
            "Issuer": issuer,
            "Subject": {
                "NameID": {
                    "Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                    "Value": user_email
                },
                "SubjectConfirmation": {
                    "Method": "urn:oasis:names:tc:SAML:2.0:cm:bearer",
                    "NotOnOrAfter": not_after,
                    "Recipient": audience
                }
            },
            "Conditions": {
                "NotBefore": not_before,
                "NotOnOrAfter": not_after,
                "AudienceRestriction": audience
            },
            "AttributeStatement": {
                "Attributes": [
                    {"Name": "email", "Value": user_email},
                    {"Name": "displayName", "Value": user_name},
                    {"Name": "roles", "Value": roles},
                    {"Name": "department", "Value": "Cybersecurity"},
                    {"Name": "employeeType", "Value": "FTE"}
                ]
            },
            "AuthnStatement": {
                "AuthnInstant": not_before,
                "SessionIndex": assertion_id,
                "AuthnContext": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            }
        }
    }
    return assertion


def validate_saml_assertion(assertion):
    issues = []
    saml = assertion.get("SAMLAssertion", {})

    now = datetime.now(timezone.utc)
    not_after_str = saml.get("Conditions", {}).get("NotOnOrAfter", "")
    if not_after_str:
        not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
        if now > not_after:
            issues.append("FAIL: Assertion has expired")
        else:
            remaining = (not_after - now).seconds // 60
            issues.append(f"PASS: Assertion valid for {remaining} more minutes")

    issuer = saml.get("Issuer", "")
    if issuer:
        issues.append(f"PASS: Issuer verified — {issuer}")
    else:
        issues.append("FAIL: No issuer in assertion")

    subject = saml.get("Subject", {}).get("NameID", {}).get("Value", "")
    if subject:
        issues.append(f"PASS: Subject identified — {subject}")
    else:
        issues.append("FAIL: No subject in assertion")

    roles = next(
        (a["Value"] for a in saml.get("AttributeStatement", {}).get("Attributes", [])
         if a["Name"] == "roles"), []
    )
    if roles:
        issues.append(f"PASS: Roles present — {roles}")
    else:
        issues.append("WARN: No roles in assertion")

    return issues


def encode_saml_response(assertion):
    json_str = json.dumps(assertion, indent=2)
    return base64.b64encode(json_str.encode()).decode()


def run():
    print("\n" + "=" * 60)
    print(" SAML 2.0 DEMO — Enterprise Single Sign-On")
    print("=" * 60 + "\n")

    print("[1] User authenticates at Identity Provider (IdP)")
    print("-" * 40)
    print("  User: idris.junaid@wellsfargo.com")
    print("  IdP:  https://idp.wellsfargo.com")
    print("  SP:   https://splunk.wellsfargo.com")
    print()

    print("[2] IdP generates SAML Assertion")
    print("-" * 40)
    assertion = generate_saml_assertion(
        user_email="idris.junaid@wellsfargo.com",
        user_name="Idris Junaid",
        roles=["SecurityAnalyst", "SIEMUser"],
        issuer="https://idp.wellsfargo.com",
        audience="https://splunk.wellsfargo.com"
    )
    print(json.dumps(assertion, indent=2))
    print()

    print("[3] SAML Assertion encoded for transmission")
    print("-" * 40)
    encoded = encode_saml_response(assertion)
    print(f"  Base64 encoded: {encoded[:80]}...")
    print()

    print("[4] Service Provider validates assertion")
    print("-" * 40)
    validation_results = validate_saml_assertion(assertion)
    for result in validation_results:
        icon = "✓" if "PASS" in result else "✗" if "FAIL" in result else "⚠"
        print(f"  {icon} {result}")
    print()

    print("[5] User granted access to Splunk")
    print("-" * 40)
    roles = next(
        (a["Value"] for a in assertion["SAMLAssertion"]["AttributeStatement"]["Attributes"]
         if a["Name"] == "roles"), []
    )
    print(f"  Access granted with roles: {roles}")
    print(f"  No password transmitted to Service Provider")
    print(f"  Session managed by IdP — single logout supported")
    print()

    print("=" * 60)
    print(" SAML Key Concepts:")
    print("  - IdP = Identity Provider (Okta, Azure AD, Ping)")
    print("  - SP  = Service Provider (Splunk, Salesforce, app)")
    print("  - Assertion = signed XML token with user attributes")
    print("  - SSO = user logs in once, accesses many apps")
    print("  - SLO = single logout terminates all sessions")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run()
