from utils.aws_session import get_boto3_session  # type: ignore

def run(profile=None):
    session = get_boto3_session(profile)
    ec2 = session.client("ec2")

    findings = audit_vpcs(ec2)
    print_findings(findings)
    return findings

def audit_vpcs(ec2_client):
    findings = []

    # Check for default VPCs
    vpcs = ec2_client.describe_vpcs()["Vpcs"]
    for vpc in vpcs:
        if vpc.get("IsDefault"):
            findings.append(f"{vpc['VpcId']}: default VPC exists")

    # Check for public route tables
    route_tables = ec2_client.describe_route_tables()["RouteTables"]
    for rt in route_tables:
        for route in rt.get("Routes", []):
            if route.get("DestinationCidrBlock") == "0.0.0.0/0":
                if "GatewayId" in route and "igw-" in route["GatewayId"]:
                    findings.append(f"{rt['RouteTableId']}: route to 0.0.0.0/0 via Internet Gateway")

    return findings

def print_findings(findings):
    if not findings:
        print("VPC Audit: No issues found.")
    else:
        print("VPC Audit Findings:")
        for issue in findings:
            print("-", issue)
