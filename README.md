# Cloud Security Configuration Scanner

A Python-based security auditing tool for AWS that scans an account for common cloud misconfigurations and reports findings in a clear, structured format.

Built as a college project to demonstrate practical cloud security concepts including least-privilege IAM, S3 bucket exposure, and network security group auditing.

## What It Does

This tool connects to an AWS account (using read-only, least-privilege credentials) and runs three security checks:

### 1. S3 Bucket Check (`checks/s3_check.py`)
Scans all S3 buckets and flags any that are publicly accessible via:
- Bucket ACL grants to "AllUsers" or "AuthenticatedUsers"
- Public bucket policies
- Disabled "Block Public Access" settings

### 2. IAM User Check (`checks/iam_check.py`)
Scans all IAM users and flags:
- Users without Multi-Factor Authentication (MFA) enabled
- Access keys older than 90 days

### 3. Security Group Check (`checks/sg_check.py`)
Scans all EC2 security groups and flags any inbound rules that expose sensitive ports (SSH, RDP, MySQL, PostgreSQL, MongoDB, Redis, etc.) or all traffic to the entire internet (`0.0.0.0/0`).

## Why This Matters

Misconfigured cloud resources are one of the leading causes of real-world data breaches. Publicly exposed S3 buckets, missing MFA, and open security groups are exactly the kinds of misconfigurations exploited in well-known incidents (e.g., the 2019 Capital One breach involved S3 data exposure). This project automates the kind of manual checks that form the basis of frameworks like the CIS AWS Foundations Benchmark.

## Project Structure

```
cloud-security-scanner/
├── checks/
│   ├── __init__.py
│   ├── s3_check.py
│   ├── iam_check.py
│   └── sg_check.py
├── main.py
└── README.md
```

## Requirements

- Python 3.8+
- boto3 (`pip install boto3`)
- An AWS account with an IAM user that has the AWS-managed `SecurityAudit` policy attached
- AWS CLI configured locally (`aws configure`) with that IAM user's access keys

## Setup

1. Clone this repository:
   ```
   git clone https://github.com/Jayasri1709/cloud-security-scanner.git
   cd cloud-security-scanner
   ```

2. Install dependencies:
   ```
   pip install boto3
   ```

3. Configure AWS credentials (use a restricted IAM user, not root):
   ```
   aws configure
   ```

4. Run the scanner:
   ```
   python main.py
   ```

## Sample Output

```
Starting Cloud Security Configuration Scan...

============================================================
 S3 PUBLIC BUCKET SECURITY SCAN
============================================================
Checking bucket: security-test-2026-vaish
  [OK] security-test-2026-vaish is private and protected

============================================================
 IAM USER SECURITY SCAN
============================================================
Checking user: security-scanner-user
  [RISK] security-scanner-user has security issues:
      - MFA is NOT enabled

============================================================
 SECURITY GROUP SCAN
============================================================
Checking security group: default (sg-0d535e2ab5e89b6ab)
  [OK] default has no internet-exposed sensitive ports

############################################################
#               FINAL SECURITY SUMMARY                    #
############################################################
TOTALS:
  High Risk items : 0
  At Risk items    : 1
  Safe items       : 2
############################################################
```

## Security Notes

- This tool is intended for **read-only auditing** using the AWS-managed `SecurityAudit` policy — it does not modify any AWS resources.
- Never commit AWS access keys or `.csv` credential files to version control.
- Always follow the principle of least privilege when creating IAM users for tools like this.

## Future Improvements

- Encryption checks for S3 buckets and EBS volumes
- CloudTrail-based root account usage detection
- Export findings to JSON/CSV/HTML report
- Multi-region scanning support
- Slack/email alerting for high-risk findings

## Author

Built as a college cloud security project to demonstrate hands-on understanding of AWS IAM, S3, EC2 security groups, and the `boto3` SDK.
