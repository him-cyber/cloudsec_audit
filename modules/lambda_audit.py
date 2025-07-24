from utils.aws_session import get_boto3_session  # type: ignore

def run(profile=None):
    session = get_boto3_session(profile)
    client = session.client("lambda")

    findings = audit_lambda(client)
    print_findings(findings)
    return findings

def audit_lambda(client):
    findings = []
    paginator = client.get_paginator("list_functions")

    for page in paginator.paginate():
        for fn in page["Functions"]:
            name = fn["FunctionName"]

            # 1. VPC Configuration
            vpc = fn.get("VpcConfig", {})
            if not vpc.get("SubnetIds"):
                findings.append(f"{name}: not configured within a VPC")

            # 2. IAM Role
            if not fn.get("Role"):
                findings.append(f"{name}: missing IAM execution role")

            # 3. Environment Variable Encryption
            env_vars = fn.get("Environment", {}).get("Variables")
            if env_vars and not fn.get("KMSKeyArn"):
                findings.append(f"{name}: environment variables unencrypted (no KMS key)")

            # 4. Timeout and Memory
            if fn.get("Timeout", 3) > 30:
                findings.append(f"{name}: excessive timeout ({fn['Timeout']}s)")
            if fn.get("MemorySize", 128) > 1024:
                findings.append(f"{name}: high memory allocation ({fn['MemorySize']} MB)")

            # 5. DLQ
            try:
                attrs = client.get_function_configuration(FunctionName=name)
                if not attrs.get("DeadLetterConfig", {}).get("TargetArn"):
                    findings.append(f"{name}: no Dead Letter Queue configured")
            except Exception as e:
                findings.append(f"{name}: error fetching DLQ config - {e}")

            # 6. Public Function URL with No Auth
            try:
                url_cfg = client.get_function_url_config(FunctionName=name)
                if url_cfg.get("AuthType") == "NONE":
                    findings.append(f"{name}: public URL with no authentication")
            except client.exceptions.ResourceNotFoundException:
                pass  # No URL config, skip

    return findings

def print_findings(findings):
    if not findings:
        print("Lambda Audit: No issues found.")
    else:
        print("Lambda Audit Findings:")
        for issue in findings:
            print("-", issue)
