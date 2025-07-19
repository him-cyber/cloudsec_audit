import boto3

def run(profile=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")

    findings = audit_users(iam)
    print_findings(findings)

def audit_users(iam_client):
    findings = []

    for user in iam_client.list_users()["Users"]:
        username = user["UserName"]

        if user_has_admin_policy(iam_client, username):
            findings.append(f"{username}: has AdministratorAccess")

        if user_has_wildcard_policy(iam_client, username):
            findings.append(f"{username}: has wildcard '*' permissions")

    return findings

def user_has_admin_policy(iam_client, username):
    policies = iam_client.list_attached_user_policies(UserName=username)["AttachedPolicies"]
    return any(policy["PolicyName"] == "AdministratorAccess" for policy in policies)

def user_has_wildcard_policy(iam_client, username):
    inline_policies = iam_client.list_user_policies(UserName=username)["PolicyNames"]
    for policy_name in inline_policies:
        policy_doc = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)["PolicyDocument"]
        statements = policy_doc["Statement"]
        statements = statements if isinstance(statements, list) else [statements]

        for stmt in statements:
            actions = stmt.get("Action", [])
            actions = actions if isinstance(actions, list) else [actions]
            if "*" in actions:
                return True
    return False

def print_findings(findings):
    if not findings:
        print("IAM Audit: No issues found.")
    else:
        print("IAM Audit Findings:")
        for issue in findings:
            print("-", issue)