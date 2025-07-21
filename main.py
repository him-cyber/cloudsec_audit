import argparse
import os

from modules import (
    iam_audit,
    s3_audit,
    sg_audit,
    terraform_linter,
    ec2_audit,
    lambda_audit,
    ecr_audit,
    vpc_audit,
    rds_audit
)

from utils.output_handler import handle_output


def main():
    parser = argparse.ArgumentParser(description="CloudSec Audit CLI")
    parser.add_argument(
        "--check",
        choices=["iam", "s3", "sg", "terraform", "ec2", "lambda", "ecr", "vpc", "rds"],
        required=True,
        help="Audit type to run"
    )
    parser.add_argument("--profile", help="Single AWS CLI profile to use (overridden by --profiles)")
    parser.add_argument("--profiles", help="Comma-separated list of AWS CLI profiles for multi-account audits")
    parser.add_argument("--file", help="Terraform file path (required for terraform check)")
    parser.add_argument("--output-file", help="Custom report filename (saved in /reports)")
    parser.add_argument("--output-format", choices=["json", "csv"], help="Output format")

    args = parser.parse_args()

    REPORTS_DIR = "reports"
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # Handle profile input
    profiles = []
    if args.profiles:
        profiles = [p.strip() for p in args.profiles.split(",")]
    elif args.profile:
        profiles = [args.profile]
    else:
        profiles = [None]

    all_findings = []

    # Run audits for each profile
    for profile in profiles:
        if args.check == "iam":
            findings = iam_audit.run(profile)
        elif args.check == "s3":
            findings = s3_audit.run(profile)
        elif args.check == "sg":
            findings = sg_audit.run(profile)
        elif args.check == "terraform":
            if not args.file:
                parser.error("--file is required for terraform check")
            findings = terraform_linter.run(args.file)
        elif args.check == "ec2":
            findings = ec2_audit.run(profile)
        elif args.check == "lambda":
            findings = lambda_audit.run(profile)
        elif args.check == "ecr":
            findings = ecr_audit.run(profile)
        elif args.check == "vpc":
            findings = vpc_audit.run(profile)
        elif args.check == "rds":
            findings = rds_audit.run(profile)
        else:
            findings = []

        prefix = profile if profile else "default"
        tagged = [f"[{prefix}] {f}" for f in findings]
        all_findings.extend(tagged)

    # Output findings
    handle_output(
        audit_type=args.check,
        findings=all_findings,
        profile=(args.profile or args.profiles),
        output_format=args.output_format,
        output_file=args.output_file
    )

if __name__ == "__main__":
    main()
