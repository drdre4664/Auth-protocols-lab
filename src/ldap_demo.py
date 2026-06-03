#!/usr/bin/env python3
"""
LDAP Demo
Demonstrates LDAP directory structure and operations without requiring
a live LDAP server — simulates the queries and responses you'd see
in an enterprise Active Directory environment.
"""

import json
from datetime import datetime


# Simulated enterprise LDAP directory
LDAP_DIRECTORY = {
    "dc=wellsfargo,dc=com": {
        "objectClass": ["top", "domain"],
        "dc": "wellsfargo",
        "children": {
            "ou=People,dc=wellsfargo,dc=com": {
                "objectClass": ["top", "organizationalUnit"],
                "ou": "People",
                "children": {
                    "uid=idris.junaid,ou=People,dc=wellsfargo,dc=com": {
                        "objectClass": ["top", "person", "organizationalPerson", "inetOrgPerson"],
                        "uid": "idris.junaid",
                        "cn": "Idris Junaid",
                        "sn": "Junaid",
                        "givenName": "Idris",
                        "mail": "idris.junaid@wellsfargo.com",
                        "telephoneNumber": "+1-704-555-0123",
                        "title": "Lead Business Execution Consultant",
                        "department": "Payments Recovery",
                        "employeeNumber": "WF-12345678",
                        "manager": "uid=manager,ou=People,dc=wellsfargo,dc=com",
                        "memberOf": [
                            "cn=payments-team,ou=Groups,dc=wellsfargo,dc=com",
                            "cn=python-developers,ou=Groups,dc=wellsfargo,dc=com"
                        ],
                        "accountStatus": "active",
                        "passwordLastSet": "2026-03-01T00:00:00Z",
                        "lastLogon": "2026-06-03T09:00:00Z"
                    },
                    "uid=john.snow,ou=People,dc=wellsfargo,dc=com": {
                        "objectClass": ["top", "person", "inetOrgPerson"],
                        "uid": "john.snow",
                        "cn": "John Snow",
                        "mail": "john.snow@wellsfargo.com",
                        "title": "Systems Administrator",
                        "department": "IT Operations",
                        "memberOf": [
                            "cn=sysadmins,ou=Groups,dc=wellsfargo,dc=com",
                            "cn=aws-admins,ou=Groups,dc=wellsfargo,dc=com"
                        ],
                        "accountStatus": "active",
                        "passwordLastSet": "2025-12-01T00:00:00Z",
                        "lastLogon": "2026-06-03T08:30:00Z"
                    }
                }
            },
            "ou=Groups,dc=wellsfargo,dc=com": {
                "objectClass": ["top", "organizationalUnit"],
                "ou": "Groups",
                "children": {
                    "cn=ctfc-analysts,ou=Groups,dc=wellsfargo,dc=com": {
                        "objectClass": ["top", "groupOfNames"],
                        "cn": "ctfc-analysts",
                        "description": "Cyber Threat Fusion Center Analysts",
                        "member": [
                            "uid=analyst1,ou=People,dc=wellsfargo,dc=com",
                            "uid=analyst2,ou=People,dc=wellsfargo,dc=com"
                        ]
                    },
                    "cn=sysadmins,ou=Groups,dc=wellsfargo,dc=com": {
                        "objectClass": ["top", "groupOfNames"],
                        "cn": "sysadmins",
                        "description": "System Administrators",
                        "member": [
                            "uid=john.snow,ou=People,dc=wellsfargo,dc=com"
                        ]
                    },
                    "cn=aws-admins,ou=Groups,dc=wellsfargo,dc=com": {
                        "objectClass": ["top", "groupOfNames"],
                        "cn": "aws-admins",
                        "description": "AWS Administrators",
                        "member": [
                            "uid=john.snow,ou=People,dc=wellsfargo,dc=com"
                        ]
                    }
                }
            },
            "ou=ServiceAccounts,dc=wellsfargo,dc=com": {
                "objectClass": ["top", "organizationalUnit"],
                "ou": "ServiceAccounts",
                "children": {
                    "uid=svc_splunk,ou=ServiceAccounts,dc=wellsfargo,dc=com": {
                        "objectClass": ["top", "person"],
                        "uid": "svc_splunk",
                        "cn": "Splunk Service Account",
                        "description": "Non-human account for Splunk SIEM",
                        "accountType": "service",
                        "passwordLastSet": "2026-01-01T00:00:00Z",
                        "passwordNeverExpires": False,
                        "memberOf": ["cn=siem-readers,ou=Groups,dc=wellsfargo,dc=com"]
                    }
                }
            }
        }
    }
}


def ldap_search(base_dn, filter_str, attributes=None):
    print(f"  ldapsearch -x -H ldap://ad.wellsfargo.com \\")
    print(f"    -b '{base_dn}' \\")
    print(f"    '{filter_str}'")
    print()

    results = []
    directory = LDAP_DIRECTORY.get("dc=wellsfargo,dc=com", {})

    def search_node(node, dn):
        if filter_str == "(objectClass=*)" or matches_filter(node, filter_str):
            if dn.endswith(base_dn) or dn == base_dn:
                entry = {"dn": dn}
                if attributes:
                    entry.update({k: v for k, v in node.items()
                                  if k in attributes and k != "children"})
                else:
                    entry.update({k: v for k, v in node.items() if k != "children"})
                results.append(entry)
        for child_dn, child_node in node.get("children", {}).items():
            search_node(child_node, child_dn)

    search_node(directory, "dc=wellsfargo,dc=com")
    return results


def matches_filter(node, filter_str):
    filter_str = filter_str.strip("()")
    if "=" in filter_str:
        attr, value = filter_str.split("=", 1)
        node_val = node.get(attr, "")
        if isinstance(node_val, list):
            return any(value.lower() in str(v).lower() for v in node_val)
        return value.lower() in str(node_val).lower()
    return False


def authenticate_user(username, password):
    user_dn = f"uid={username},ou=People,dc=wellsfargo,dc=com"
    users = LDAP_DIRECTORY["dc=wellsfargo,dc=com"]["children"]
    people = users.get("ou=People,dc=wellsfargo,dc=com", {}).get("children", {})
    user = people.get(user_dn)

    if not user:
        return False, "User not found"
    if user.get("accountStatus") != "active":
        return False, "Account disabled"
    return True, user


def run():
    print("\n" + "=" * 60)
    print(" LDAP DEMO — Enterprise Directory Services")
    print("=" * 60 + "\n")

    print("[Concept] What is LDAP?")
    print("-" * 40)
    print("  LDAP = Lightweight Directory Access Protocol")
    print("  It's the protocol used to query Active Directory")
    print("  Every enterprise uses AD/LDAP for user management")
    print("  IAM tools (Okta, SailPoint) sync FROM LDAP")
    print()

    print("[1] LDAP Directory Structure (DN = Distinguished Name)")
    print("-" * 40)
    print("  dc=wellsfargo,dc=com          ← Domain root")
    print("  └── ou=People                 ← Organizational Unit")
    print("  │   ├── uid=idris.junaid      ← User entry")
    print("  │   └── uid=john.snow         ← User entry")
    print("  ├── ou=Groups                 ← Groups OU")
    print("  │   ├── cn=ctfc-analysts      ← Security group")
    print("  │   └── cn=sysadmins          ← Admin group")
    print("  └── ou=ServiceAccounts        ← Non-human accounts")
    print("      └── uid=svc_splunk        ← Service account")
    print()

    print("[2] Search for user by email")
    print("-" * 40)
    print("  Query: Find user with email idris.junaid@wellsfargo.com")
    print()
    results = ldap_search(
        "ou=People,dc=wellsfargo,dc=com",
        "(mail=idris.junaid@wellsfargo.com)",
        attributes=["cn", "mail", "title", "department", "memberOf"]
    )
    for r in results:
        for k, v in r.items():
            print(f"  {k:<20}: {v}")
    print()

    print("[3] Authenticate user (LDAP Bind)")
    print("-" * 40)
    print("  Attempting bind as: idris.junaid")
    success, result = authenticate_user("idris.junaid", "password123")
    if success:
        print(f"  ✓ Authentication successful")
        print(f"  ✓ Account status: {result.get('accountStatus')}")
        print(f"  ✓ Groups: {result.get('memberOf', [])}")
    else:
        print(f"  ✗ Authentication failed: {result}")
    print()

    print("[4] Find all members of security group")
    print("-" * 40)
    print("  Query: Who is in cn=aws-admins?")
    print()
    groups = LDAP_DIRECTORY["dc=wellsfargo,dc=com"]["children"]
    group_dn = "cn=aws-admins,ou=Groups,dc=wellsfargo,dc=com"
    group = groups.get("ou=Groups,dc=wellsfargo,dc=com", {}).get("children", {}).get(group_dn, {})
    members = group.get("member", [])
    print(f"  Group: {group_dn}")
    print(f"  Members:")
    for m in members:
        print(f"    - {m}")
    print()

    print("[5] Service Account Audit")
    print("-" * 40)
    print("  Query: List all service accounts (non-human identities)")
    svc_accounts = LDAP_DIRECTORY["dc=wellsfargo,dc=com"]["children"]
    svc_ou = svc_accounts.get("ou=ServiceAccounts,dc=wellsfargo,dc=com", {}).get("children", {})
    for dn, account in svc_ou.items():
        pwd_set = account.get("passwordLastSet", "unknown")
        never_expires = account.get("passwordNeverExpires", False)
        status = "⚠ PASSWORD NEVER EXPIRES" if never_expires else "✓ Password rotation configured"
        print(f"  Account: {account.get('uid')}")
        print(f"  Purpose: {account.get('description')}")
        print(f"  Password last set: {pwd_set}")
        print(f"  Status: {status}")
    print()

    print("=" * 60)
    print(" LDAP Key Concepts:")
    print("  DN  = Distinguished Name (unique identifier)")
    print("  OU  = Organizational Unit (folder)")
    print("  CN  = Common Name (object name)")
    print("  DC  = Domain Component (domain parts)")
    print("  Bind = authenticate to LDAP server")
    print("  IAM tools sync users FROM LDAP/AD")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run()
