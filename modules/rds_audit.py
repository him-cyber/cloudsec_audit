import boto3

def run(profile=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    rds = session.client("rds")

    findings = audit_rds_instances(rds)
    print_findings(findings)
    return findings

def audit_rds_instances(rds_client):
    findings = []
    instances = rds_client.describe_db_instances()["DBInstances"]

    for db in instances:
        db_id = db["DBInstanceIdentifier"]

        if db.get("PubliclyAccessible"):
            findings.append(f"{db_id}: publicly accessible")

        if not db.get("StorageEncrypted"):
            findings.append(f"{db_id}: storage not encrypted")

        if db.get("BackupRetentionPeriod", 0) == 0:
            findings.append(f"{db_id}: no backup retention configured")

        if not db.get("MultiAZ"):
            findings.append(f"{db_id}: not deployed in Multi-AZ")

    return findings

def print_findings(findings):
    if not findings:
        print("RDS Audit: No issues found.")
    else:
        print("RDS Audit Findings:")
        for issue in findings:
            print("-", issue)
