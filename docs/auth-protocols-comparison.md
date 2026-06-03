# Authentication Protocols Comparison

## Quick Reference

| Protocol | Type | Token Format | Primary Use | Enterprise Tools |
|----------|------|-------------|-------------|-----------------|
| SAML 2.0 | Federated SSO | XML Assertion | B2B, legacy apps | Okta, Ping, ADFS |
| OAuth 2.0 | Authorization | JWT/opaque | API access | Okta, Azure AD |
| OIDC | Authentication | JWT (ID Token) | Modern SSO | Okta, Azure AD, Google |
| LDAP | Directory | N/A (protocol) | User store, auth | Active Directory |

---

## SAML 2.0

**When to use:** Legacy enterprise apps, B2B federation, SAML-only SPs

**Flow:**
1. User accesses SP (e.g., Splunk)
2. SP redirects to IdP with SAML Request
3. User authenticates at IdP
4. IdP sends SAML Response (XML assertion) to SP
5. SP validates assertion and grants access

**Key security controls:**
- Assertions are XML-signed (prevents tampering)
- Short assertion validity (minutes, not hours)
- Audience restriction (assertion only valid for intended SP)
- Replay prevention via assertion ID tracking

---

## OAuth 2.0

**When to use:** API authorization, delegated access, service-to-service

**Grant Types:**
- **Authorization Code** — Web apps (most secure, use PKCE)
- **Client Credentials** — Service-to-service (no user)
- **Device Code** — CLI tools, smart devices

**Key security controls:**
- Short-lived access tokens (1 hour)
- Refresh token rotation
- Scopes limit token permissions
- PKCE prevents authorization code interception

---

## OpenID Connect

**When to use:** Modern SSO, mobile apps, anything needing user identity

**Built on OAuth 2.0, adds:**
- ID Token (JWT with user claims)
- UserInfo endpoint
- Standard claims (sub, email, name, etc.)
- Discovery endpoint (/.well-known/openid-configuration)

**Key JWT claims:**
- `sub` — subject (unique user ID, never changes)
- `iss` — issuer (who created the token)
- `aud` — audience (who the token is for)
- `exp` — expiry timestamp
- `amr` — authentication methods used
- `acr` — authentication context class

---

## LDAP

**When to use:** User directory, group management, legacy authentication

**Enterprise context:**
- Active Directory IS an LDAP server
- All IAM tools (Okta, SailPoint) sync FROM AD/LDAP
- Provisioning = creating entries in LDAP
- Deprovisioning = disabling/deleting LDAP entries
- Group membership = authorization in many systems

**Security considerations:**
- Use LDAPS (LDAP over SSL/TLS) — never plain LDAP
- Bind accounts should have minimal permissions
- Monitor failed bind attempts (brute force indicator)
- Service accounts require separate password policy
