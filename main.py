"""
main.py
------------
Main entry point for the Cloud Security Configuration Scanner.
Runs all individual checks (S3, IAM, etc.) and prints a combined
summary report at the end.

Part of: Cloud Security Configuration Scanner (college project)
"""

from datetime import datetime
from checks.s3_check import scan_buckets
from checks.iam_check import scan_iam_users
from checks.sg_check import scan_security_groups


def print_summary(s3_findings, iam_findings, sg_findings):
    """Print a combined summary of all findings across all checks."""
    print("\n")
    print("#" * 60)
    print("#" + " " * 15 + "FINAL SECURITY SUMMARY" + " " * 21 + "#")
    print("#" * 60)
    print(f"Scan run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    total_high_risk = 0
    total_at_risk = 0
    total_safe = 0

    print("\n[ S3 BUCKET FINDINGS ]")
    if not s3_findings:
        print("  No buckets found.")
    for item in s3_findings:
        print(f"  - {item['bucket']}: {item['status']}")
        if item["status"] == "PUBLIC":
            total_high_risk += 1
        elif item["status"] == "AT RISK":
            total_at_risk += 1
        else:
            total_safe += 1

    print("\n[ IAM USER FINDINGS ]")
    if not iam_findings:
        print("  No IAM users found.")
    for item in iam_findings:
        print(f"  - {item['user']}: {item['status']}")
        if item["status"] == "AT RISK":
            total_at_risk += 1
        else:
            total_safe += 1

    print("\n[ SECURITY GROUP FINDINGS ]")
    if not sg_findings:
        print("  No security groups found.")
    for item in sg_findings:
        print(f"  - {item['group_name']} ({item['group_id']}): {item['status']}")
        if item["status"] == "EXPOSED":
            total_high_risk += 1
        else:
            total_safe += 1

    print("\n" + "-" * 60)
    print("TOTALS:")
    print(f"  High Risk items : {total_high_risk}")
    print(f"  At Risk items   : {total_at_risk}")
    print(f"  Safe items      : {total_safe}")
    print("#" * 60)


def main():
    print("Starting Cloud Security Configuration Scan...\n")

    # Run S3 check
    s3_findings = scan_buckets()

    print("\n")

    # Run IAM check
    iam_findings = scan_iam_users()

    print("\n")

    # Run Security Group check
    sg_findings = scan_security_groups()

    # Print combined summary
    print_summary(s3_findings, iam_findings, sg_findings)


if __name__ == "__main__":
    main()