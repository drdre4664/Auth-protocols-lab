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
