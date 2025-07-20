import boto3

def run(profile=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    ec2 = session.client("ec2")

    findings = audit_security_groups(ec2)
    print_findings(findings)
    return findings

def audit_security_groups(ec2_client):
    findings = []
    security_groups = ec2_client.describe_security_groups()["SecurityGroups"]

    for sg in security_groups:
        sg_name = sg.get("GroupName", sg["GroupId"])
        issues = check_rules(sg["IpPermissions"])
        for issue in issues:
            findings.append(f"{sg_name}: {issue}")

    return findings

def check_rules(permissions):
    issues = []
    for perm in permissions:
        ip_ranges = perm.get("IpRanges", [])
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        for ip in ip_ranges:
            cidr = ip.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                if from_port in [22, 3389]:
                    issues.append(f"port {from_port} open to the world")
                elif from_port is not None and to_port is not None and (to_port - from_port) > 100:
                    issues.append(f"wide port range {from_port}-{to_port} open to the world")
    return issues

def print_findings(findings):
    if not findings:
        print("Security Group Audit: No issues found.")
    else:
        print("Security Group Audit Findings:")
        for issue in findings:
            print("-", issue)
