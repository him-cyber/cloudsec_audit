import argparse

from modules import iam_audit, s3_audit, sg_audit, terraform_linter, ec2_audit, lambda_audit

def main():
    parser = argparse.ArgumentParser(description="CloudSec Audit CLI")
    parser.add_argument("--check", choices=["iam", "s3", "sg", "terraform", "ec2", "lambda"], required=True, help="Audit type to run")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--file", help="Terraform file path (required for terraform check)")

    args = parser.parse_args()

    if args.check == "iam":
        findings = iam_audit.run(args.profile)
    elif args.check == "s3":
        findings = s3_audit.run(args.profile)
    elif args.check == "sg":
        findings = sg_audit.run(args.profile)
    elif args.check == "terraform":
        if not args.file:
            parser.error("--file is required for terraform check")
        findings = terraform_linter.run(args.file)
    elif args.check == "ec2":
        findings = ec2_audit.run(args.profile)
    elif args.check == "lambda":
        findings = lambda_audit.run(args.profile)

if __name__ == "__main__":
    main()
