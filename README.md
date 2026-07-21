# Authentication Protocols Lab

## Overview
A production-grade demonstration of enterprise authentication protocols used in
regulated financial environments. Covers SAML 2.0, OAuth 2.0, OpenID Connect (OIDC),
and LDAP — the four protocols that appear most frequently in enterprise IAM implementations
at organizations like Wells Fargo, JPMorgan, and Bank of America.

## Why Authentication Protocols Matter
Authentication protocols are the foundation of Zero Trust architecture. Every IAM
platform (Okta, SailPoint, Azure AD, CyberArk) is built on top of these protocols.
Understanding them at a deep level is what separates a security analyst from a
security engineer.

## Protocols Covered

| Protocol | Purpose | Enterprise Use Case |
|----------|---------|---------------------|
| SAML 2.0 | Federated SSO | Corporate SSO, B2B federation |
| OAuth 2.0 | Authorization delegation | API access, third-party integrations |
| OpenID Connect | Identity layer on OAuth | Modern SSO, mobile apps |
| LDAP | Directory services | Active Directory, user provisioning |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                Enterprise Identity Stack                  │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │  SAML    │  │ OAuth2   │  │  OIDC    │  │  LDAP  │ │
│  │  2.0     │  │          │  │          │  │        │ │
│  │          │  │          │  │          │  │        │ │
│  │ XML-based│  │Token-based│  │JWT-based │  │DN-based│ │
│  │ Federated│  │API access │  │Identity  │  │Directory│ │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘ │
│                         │                               │
│                         ▼                               │
│              Identity Provider (IdP)                    │
│         (Okta / Azure AD / Ping Identity)               │
└─────────────────────────────────────────────────────────┘
```

## Repository Structure
```
auth-protocols-lab/
├── src/
│   ├── saml_demo.py          # SAML 2.0 assertion generation and validation
│   ├── oauth2_demo.py        # OAuth 2.0 flows (Authorization Code, Client Credentials)
│   ├── oidc_demo.py          # OpenID Connect token validation and claims
│   └── ldap_demo.py          # LDAP directory operations and authentication
├── docs/
│   ├── saml-explained.md     # SAML deep dive with flow diagrams
│   ├── oauth2-explained.md   # OAuth 2.0 grant types explained
│   ├── oidc-explained.md     # OIDC vs OAuth2 comparison
│   └── ldap-explained.md     # LDAP structure and enterprise use
└── diagrams/
    └── auth-flows.md         # Authentication flow comparisons
```

## Skills Demonstrated
- SAML 2.0 assertion structure and validation
- OAuth 2.0 Authorization Code and Client Credentials flows
- JWT token generation, signing, and validation
- OpenID Connect ID token claims and userinfo
- LDAP directory structure (DN, OU, CN, attributes)
- Authentication vs Authorization concepts
- Federation and SSO architecture
- Token security (signing, expiry, scope)

---

## Lessons Learned

### The Core Distinction — Authentication vs Authorization
The most important concept in this lab: SAML handles authentication (who you are), OAuth 2.0 handles authorization (what you're allowed to do), OIDC handles both. LDAP is the directory backbone that all three query. Confusing authentication and authorization is one of the most common mistakes in IAM design — getting this distinction right is foundational.

### SAML — Enterprise SSO in Real Life
SAML is exactly what happens when you log into a Wells Fargo laptop and get automatic access to Splunk, ServiceNow, and Pluralsight without re-entering a password. You authenticate once at the IdP (Azure AD or Okta). The IdP generates a signed SAML Assertion containing your identity, roles, department, and session validity. Each Service Provider (Splunk, Salesforce) validates that assertion — no password ever reaches the SP. The `AudienceRestriction` field locks the assertion to one specific SP so it can't be replayed against other apps.

### OAuth 2.0 — Plaid and API Access
OAuth 2.0 is what Plaid uses when you connect your bank account to a fintech app. You authenticate at your bank, your bank issues a token with specific scopes (read balance, read transactions — nothing else), and the app uses that token. Your bank password never touches the app. Two flows matter:
- **Authorization Code Flow** — human is involved, browser redirects, auth code exchanged for token
- **Client Credentials Flow** — machine to machine, no user, service authenticates directly. This is how SOAR automation calls security APIs in production.

### JWT — The Token Format Behind OAuth and OIDC
Every access token and ID token in OAuth/OIDC is a JWT (JSON Web Token). Always starts with `eyJ` — that's Base64 for `{"`. Three parts separated by dots: header (algorithm), payload (claims), signature (proof of integrity). The token is self-contained — the API validates it without calling back to the auth server, which is why JWTs are fast and scalable.

### OIDC — OAuth Plus Identity
OIDC adds an ID Token on top of OAuth's access token. The ID Token contains identity claims: `sub` (permanent unique user ID that never changes even if email changes), `email`, `name`, `groups`, `amr` (authentication methods used). The `amr` claim is critical in banking — it tells the app whether MFA was used. Apps can refuse access or require step-up authentication if MFA isn't in the `amr` list.

### LDAP — The Backbone Everything Else Queries
LDAP is Active Directory's protocol. When you log into a corporate laptop, Windows sends your credentials to AD via LDAP Bind. Every user has a Distinguished Name: `uid=idris.junaid,ou=People,dc=wellsfargo,dc=com`. When Okta, Azure AD, or SailPoint need to know who you are and what groups you belong to, they sync from LDAP. IAM tools don't replace LDAP — they sit on top of it.

### Service Account Risk in LDAP
The LDAP demo showed `svc_splunk` — a non-human service account with a password last set on 2026-01-01. In a real audit, this is a finding. Service accounts with stale passwords, excessive group memberships, or no password rotation are high-risk targets — exactly what the Zero Trust IAM lab covered. LDAP is where you discover these accounts and audit them.

### How All Four Work Together in Production
At Wells Fargo, all four run simultaneously:
- **LDAP** — master directory of every user, group, and service account
- **SAML** — SSO into legacy enterprise apps (older internal systems)
- **OIDC** — SSO into modern apps, enforces MFA via `amr` claim
- **OAuth 2.0** — secures APIs, enables machine-to-machine authentication for automation
