"""
s3_check.py
------------
Scans all S3 buckets in the AWS account and flags any that are
publicly accessible (via ACL or bucket policy).

Part of: Cloud Security Configuration Scanner (college project)
"""

import boto3
from botocore.exceptions import ClientError


def get_all_buckets(s3_client):
    """Return a list of all bucket names in the account."""
    response = s3_client.list_buckets()
    return [bucket["Name"] for bucket in response["Buckets"]]


def check_bucket_acl(s3_client, bucket_name):
    """
    Check the bucket ACL for public access grants.
    Returns True if public, False otherwise.
    """
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl["Grants"]:
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True
        return False
    except ClientError as e:
        print(f"  [!] Could not check ACL for {bucket_name}: {e}")
        return None


def check_bucket_policy_status(s3_client, bucket_name):
    """
    Use AWS's own public-access evaluation for the bucket policy.
    Returns True if public, False if not, None if no policy exists.
    """
    try:
        status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        return status["PolicyStatus"]["IsPublic"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return None
        print(f"  [!] Could not check policy for {bucket_name}: {e}")
        return None


def check_public_access_block(s3_client, bucket_name):
    """
    Check if the bucket has the 'Block Public Access' setting enabled.
    Returns True if fully blocked, False if not fully blocked.
    """
    try:
        config = s3_client.get_public_access_block(Bucket=bucket_name)
        settings = config["PublicAccessBlockConfiguration"]
        return all(settings.values())
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False
        print(f"  [!] Could not check public access block for {bucket_name}: {e}")
        return False


def scan_buckets():
    """Main scan function - checks every bucket and prints a report."""
    s3_client = boto3.client("s3")

    print("=" * 60)
    print(" S3 PUBLIC BUCKET SECURITY SCAN")
    print("=" * 60)

    buckets = get_all_buckets(s3_client)

    if not buckets:
        print("No S3 buckets found in this account.")
        return []

    findings = []

    for bucket_name in buckets:
        print(f"\nChecking bucket: {bucket_name}")

        is_public_acl = check_bucket_acl(s3_client, bucket_name)
        is_public_policy = check_bucket_policy_status(s3_client, bucket_name)
        is_blocked = check_public_access_block(s3_client, bucket_name)

        risk_found = False
        reasons = []

        if is_public_acl:
            risk_found = True
            reasons.append("Public ACL grant detected")

        if is_public_policy:
            risk_found = True
            reasons.append("Bucket policy allows public access")

        if not is_blocked:
            reasons.append("Block Public Access is NOT fully enabled")

        if risk_found:
            print(f"  [HIGH RISK] {bucket_name} is PUBLICLY ACCESSIBLE")
            for reason in reasons:
                print(f"      - {reason}")
            findings.append({
                "bucket": bucket_name,
                "status": "PUBLIC",
                "reasons": reasons
            })
        elif not is_blocked:
            print(f"  [MEDIUM RISK] {bucket_name} is not public now, but protection is not fully enabled")
            findings.append({
                "bucket": bucket_name,
                "status": "AT RISK",
                "reasons": reasons
            })
        else:
            print(f"  [OK] {bucket_name} is private and protected")
            findings.append({
                "bucket": bucket_name,
                "status": "SAFE",
                "reasons": []
            })

    print("\n" + "=" * 60)
    print(" SCAN COMPLETE")
    print("=" * 60)

    return findings


if __name__ == "__main__":
    scan_buckets()
