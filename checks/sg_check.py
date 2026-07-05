"""
sg_check.py
------------
Scans all EC2 Security Groups in the AWS account and flags any
inbound rules that expose sensitive ports to the entire internet
(0.0.0.0/0 or ::/0).

Part of: Cloud Security Configuration Scanner (college project)
"""

import boto3
from botocore.exceptions import ClientError

# Ports considered sensitive if open to the whole internet
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}

OPEN_TO_WORLD_IPV4 = "0.0.0.0/0"
OPEN_TO_WORLD_IPV6 = "::/0"


def get_all_security_groups(ec2_client):
    """Return a list of all security groups in the account/region."""
    groups = []
    paginator = ec2_client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        groups.extend(page["SecurityGroups"])
    return groups


def check_group_rules(sg):
    """
    Inspect a single security group's inbound rules for exposure to
    the whole internet on sensitive (or all) ports.
    Returns a list of issue strings.
    """
    issues = []

    for perm in sg.get("IpPermissions", []):
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        protocol = perm.get("IpProtocol")

        # Check IPv4 open ranges
        open_ranges = [r["CidrIp"] for r in perm.get("IpRanges", [])
                       if r.get("CidrIp") == OPEN_TO_WORLD_IPV4]
        # Check IPv6 open ranges
        open_ranges += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])
                         if r.get("CidrIpv6") == OPEN_TO_WORLD_IPV6]

        if not open_ranges:
            continue

        # protocol "-1" means ALL traffic/ports allowed
        if protocol == "-1":
            issues.append("ALL ports/protocols open to the entire internet (0.0.0.0/0)")
            continue

        if from_port is None or to_port is None:
            continue

        # Check if any sensitive port falls within the allowed range
        for port, name in SENSITIVE_PORTS.items():
            if from_port <= port <= to_port:
                issues.append(
                    f"Port {port} ({name}) open to the entire internet ({protocol.upper()})"
                )

    return issues


def scan_security_groups():
    """Main scan function - checks every security group and prints a report."""
    ec2_client = boto3.client("ec2")

    print("=" * 60)
    print(" SECURITY GROUP SCAN")
    print("=" * 60)

    try:
        groups = get_all_security_groups(ec2_client)
    except ClientError as e:
        print(f"  [!] Could not list security groups: {e}")
        return []

    if not groups:
        print("No security groups found in this region.")
        return []

    findings = []

    for sg in groups:
        group_id = sg["GroupId"]
        group_name = sg.get("GroupName", "N/A")

        print(f"\nChecking security group: {group_name} ({group_id})")

        issues = check_group_rules(sg)

        if issues:
            print(f"  [HIGH RISK] {group_name} has exposed rules:")
            for issue in issues:
                print(f"      - {issue}")
            findings.append({
                "group_id": group_id,
                "group_name": group_name,
                "status": "EXPOSED",
                "issues": issues
            })
        else:
            print(f"  [OK] {group_name} has no internet-exposed sensitive ports")
            findings.append({
                "group_id": group_id,
                "group_name": group_name,
                "status": "SAFE",
                "issues": []
            })

    print("\n" + "=" * 60)
    print(" SCAN COMPLETE")
    print("=" * 60)

    return findings


if __name__ == "__main__":
    scan_security_groups()
