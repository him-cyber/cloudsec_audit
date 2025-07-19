import boto3

def run(profile=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    s3 = session.client("s3")

    findings = audit_buckets(s3)
    print_findings(findings)

def audit_buckets(s3_client):
    findings = []
    buckets = s3_client.list_buckets()["Buckets"]

    for bucket in buckets:
        name = bucket["Name"]

        if is_public(s3_client, name):
            findings.append(f"{name}: publicly accessible")

        if not block_public_access_enabled(s3_client, name):
            findings.append(f"{name}: Block Public Access settings not enforced")

        if not has_encryption(s3_client, name):
            findings.append(f"{name}: no default encryption")

        if not has_versioning(s3_client, name):
            findings.append(f"{name}: versioning not enabled")

    return findings

def is_public(s3_client, bucket_name):
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl["Grants"]:
            uri = grant.get("Grantee", {}).get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True
    except Exception:
        pass
    return False

def block_public_access_enabled(s3_client, bucket_name):
    try:
        settings = s3_client.get_public_access_block(Bucket=bucket_name)
        config = settings["PublicAccessBlockConfiguration"]
        return all(config.values())
    except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        return False

def has_encryption(s3_client, bucket_name):
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return True
    except s3_client.exceptions.ClientError:
        return False

def has_versioning(s3_client, bucket_name):
    status = s3_client.get_bucket_versioning(Bucket=bucket_name)
    return status.get("Status") == "Enabled"

def print_findings(findings):
    if not findings:
        print("S3 Audit: No issues found.")
    else:
        print("S3 Audit Findings:")
        for issue in findings:
            print("-", issue)
