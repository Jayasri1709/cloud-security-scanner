"""
iam_check.py
------------
Scans all IAM users in the AWS account and flags any that do NOT
have MFA (Multi-Factor Authentication) enabled. Also flags any
access keys older than 90 days, since old unrotated keys are a
common security risk.

Part of: Cloud Security Configuration Scanner (college project)
"""

import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

KEY_AGE_WARNING_DAYS = 90


def get_all_users(iam_client):
    """Return a list of all IAM usernames in the account."""
    users = []
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            users.append(user["UserName"])
    return users


def check_mfa_enabled(iam_client, username):
    """
    Check if a given IAM user has at least one MFA device registered.
    Returns True if MFA is enabled, False otherwise.
    """
    try:
        response = iam_client.list_mfa_devices(UserName=username)
        return len(response["MFADevices"]) > 0
    except ClientError as e:
        print(f"  [!] Could not check MFA for {username}: {e}")
        return None


def check_old_access_keys(iam_client, username):
    """
    Check for access keys older than KEY_AGE_WARNING_DAYS.
    Returns a list of dicts describing any old keys found.
    """
    old_keys = []
    try:
        response = iam_client.list_access_keys(UserName=username)
        for key in response["AccessKeyMetadata"]:
            create_date = key["CreateDate"]
            age_days = (datetime.now(timezone.utc) - create_date).days
            if age_days > KEY_AGE_WARNING_DAYS:
                old_keys.append({
                    "key_id": key["AccessKeyId"],
                    "age_days": age_days,
                    "status": key["Status"]
                })
        return old_keys
    except ClientError as e:
        print(f"  [!] Could not check access keys for {username}: {e}")
        return []


def scan_iam_users():
    """Main scan function - checks every IAM user and prints a report."""
    iam_client = boto3.client("iam")

    print("=" * 60)
    print(" IAM USER SECURITY SCAN")
    print("=" * 60)

    usernames = get_all_users(iam_client)

    if not usernames:
        print("No IAM users found in this account.")
        return []

    findings = []

    for username in usernames:
        print(f"\nChecking user: {username}")

        has_mfa = check_mfa_enabled(iam_client, username)
        old_keys = check_old_access_keys(iam_client, username)

        issues = []

        if has_mfa is False:
            issues.append("MFA is NOT enabled")

        for key in old_keys:
            issues.append(
                f"Access key {key['key_id']} is {key['age_days']} days old "
                f"(status: {key['status']})"
            )

        if issues:
            print(f"  [RISK] {username} has security issues:")
            for issue in issues:
                print(f"      - {issue}")
            findings.append({
                "user": username,
                "status": "AT RISK",
                "issues": issues
            })
        else:
            print(f"  [OK] {username} has MFA enabled and no old access keys")
            findings.append({
                "user": username,
                "status": "SAFE",
                "issues": []
            })

    print("\n" + "=" * 60)
    print(" SCAN COMPLETE")
    print("=" * 60)

    return findings


if __name__ == "__main__":
    scan_iam_users()
