import argparse
import os
import json
import csv

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

def write_report(findings, output_file, output_format):
    if output_format == "json":
        with open(output_file, "w") as f:
            json.dump(findings, f, indent=2)
    elif output_format == "csv":
        with open(output_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Finding"])
            for item in findings:
                writer.writerow([item])

def main():
    parser = argparse.ArgumentParser(description="CloudSec Audit CLI")
    parser.add_argument(
        "--check",
        choices=["iam", "s3", "sg", "terraform", "ec2", "lambda", "ecr", "vpc", "rds"],
        required=True,
        help="Audit type to run"
    )
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--file", help="Terraform file path (required for terraform check)")
    parser.add_argument("--output-file", help="File to save report (saved to /reports directory)")
    parser.add_argument("--output-format", choices=["json", "csv"], help="Output format")

    args = parser.parse_args()

    # Ensure reports/ directory
    REPORTS_DIR = "reports"
    os.makedirs(REPORTS_DIR, exist_ok=True)

    if args.output_file:
        filename = os.path.basename(args.output_file)
        args.output_file = os.path.join(REPORTS_DIR, filename)

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
    elif args.check == "ecr":
        findings = ecr_audit.run(args.profile)
    elif args.check == "vpc":
        findings = vpc_audit.run(args.profile)
    elif args.check == "rds":
        findings = rds_audit.run(args.profile)

    if args.output_file and args.output_format:
        write_report(findings, args.output_file, args.output_format)

if __name__ == "__main__":
    main()
