import re
import os

def run(tf_file_path):
    if not tf_file_path or not os.path.isfile(tf_file_path):
        print(f"[ERROR] Terraform file not found: {tf_file_path}")
        return

    try:
        with open(tf_file_path, "r") as file:
            content = file.read()
    except Exception as e:
        print(f"[ERROR] Failed to read file: {tf_file_path} - {e}")
        return

    findings = audit_terraform(content)
    print_findings(findings)
    return findings

def audit_terraform(tf_content):
    findings = []

    # Security Group checks
    sg_issues = re.findall(r'resource "aws_security_group".*?{(.*?)}', tf_content, re.DOTALL)
    for sg in sg_issues:
        if '0.0.0.0/0' in sg:
            findings.append("Security group ingress open to 0.0.0.0/0")

    # EC2 volume encryption checks
    ebs_issues = re.findall(r'resource "aws_instance".*?{(.*?)}', tf_content, re.DOTALL)
    for instance in ebs_issues:
        if re.search(r'encrypted\s*=\s*false', instance) or 'encrypted' not in instance:
            findings.append("EC2 instance with unencrypted EBS volume")

    # S3 bucket checks
    s3_issues = re.findall(r'resource "aws_s3_bucket".*?{(.*?)}', tf_content, re.DOTALL)
    for bucket in s3_issues:
        if re.search(r'acl\s*=\s*"public-read"', bucket) or re.search(r'acl\s*=\s*"public-write"', bucket):
            findings.append("S3 bucket has public ACL configuration")
        if 'server_side_encryption_configuration' not in bucket:
            findings.append("S3 bucket without default encryption")

    return findings

def print_findings(findings):
    if not findings:
        print("Terraform Audit: No issues found.")
    else:
        print("Terraform Audit Findings:")
        for issue in findings:
            print("-", issue)
