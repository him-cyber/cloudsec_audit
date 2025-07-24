from datetime import datetime, timezone, timedelta
from utils.aws_session import get_boto3_session  # ✅ shared helper

def run(profile=None):
    session = get_boto3_session(profile)  # ✅ unified session loader
    client = session.client("ecr")

    findings = audit_ecr(client)
    print_findings(findings)
    return findings

def audit_ecr(client):
    findings = []
    repos = client.describe_repositories()["repositories"]

    for repo in repos:
        name = repo["repositoryName"]

        # Check Lifecycle Policy
        try:
            client.get_lifecycle_policy(repositoryName=name)
        except client.exceptions.LifecyclePolicyNotFoundException:
            findings.append(f"{name}: no lifecycle policy configured")

        # Check Scan-on-Push
        scan_conf = repo.get("imageScanningConfiguration", {})
        if not scan_conf.get("scanOnPush"):
            findings.append(f"{name}: scanning on push is disabled")

        # Check Repository Policy (Public Access)
        try:
            policy = client.get_repository_policy(repositoryName=name)
            if '"Principal":"*"' in policy.get("policyText", ""):
                findings.append(f"{name}: repository is publicly accessible")
        except client.exceptions.RepositoryPolicyNotFoundException:
            pass  # No policy = secure by default

        # Check Images
        images = client.describe_images(repositoryName=name)["imageDetails"]
        for image in images:
            tags = image.get("imageTags", [])
            pushed_at = image.get("imagePushedAt", datetime.now(timezone.utc))

            # Check image tagging
            if "latest" in tags:
                findings.append(f"{name}: image {image['imageDigest']} tagged 'latest'")
            if not tags:
                findings.append(f"{name}: image {image['imageDigest']} has no tag")

            # Check image age
            if pushed_at < datetime.now(timezone.utc) - timedelta(days=365):
                findings.append(f"{name}: image {image['imageDigest']} older than 365 days")

    return findings

def print_findings(findings):
    if not findings:
        print("ECR Audit: No issues found.")
    else:
        print("ECR Audit Findings:")
        for issue in findings:
            print("-", issue)
