import argparse
from modules import iam_audit, s3_audit, ec2_audit, sg_audit, terraform_linter

def main():
    parser = argparse.ArgumentParser(description="CloudSec Audit CLI")
    parser.add_argument('--check', nargs='+', required=True,
                        help='Modules to audit: iam, s3, ec2, sg, terraform, all')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--tf-file', help='Path to Terraform file (.tf) to audit')
    args = parser.parse_args()

    if "iam" in args.check or "all" in args.check:
        iam_audit.run(profile=args.profile)

    if "s3" in args.check or "all" in args.check:
        s3_audit.run(profile=args.profile)

    if "ec2" in args.check or "all" in args.check:
        ec2_audit.run(profile=args.profile)

    if "sg" in args.check or "all" in args.check:
        sg_audit.run(profile=args.profile)

    if "terraform" in args.check or "all" in args.check:
        if not args.tf_file:
            print("Terraform file path required. Use --tf-file path/to/file.tf")
        else:
            terraform_linter.run(tf_file_path=args.tf_file)

if __name__ == "__main__":
    main()
