from utils.aws_session import get_boto3_session # type: ignore

def run(profile=None):
    session = get_boto3_session(profile)
    ec2 = session.client("ec2")

    findings = audit_instances(ec2)
    print_findings(findings)
    return findings

def audit_instances(ec2_client):
    findings = []
    reservations = ec2_client.describe_instances().get("Reservations", [])

    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            instance_id = instance.get("InstanceId")

            if not has_iam_role(instance):
                findings.append(f"{instance_id}: no IAM role attached")

            if has_unencrypted_volumes(ec2_client, instance):
                findings.append(f"{instance_id}: has unencrypted EBS volume(s)")

            if is_publicly_accessible(instance):
                findings.append(f"{instance_id}: publicly accessible via public IP")

    return findings

def has_iam_role(instance):
    return "IamInstanceProfile" in instance

def has_unencrypted_volumes(ec2_client, instance):
    volumes = [
        mapping["Ebs"]["VolumeId"]
        for mapping in instance.get("BlockDeviceMappings", [])
        if "Ebs" in mapping and "VolumeId" in mapping["Ebs"]
    ]
    if not volumes:
        return False

    vol_data = ec2_client.describe_volumes(VolumeIds=volumes).get("Volumes", [])
    return any(not vol.get("Encrypted", True) for vol in vol_data)

def is_publicly_accessible(instance):
    return "PublicIpAddress" in instance

def print_findings(findings):
    if not findings:
        print("EC2 Audit: No issues found.")
    else:
        print("EC2 Audit Findings:")
        for issue in findings:
            print("-", issue)
