# CloudSec Audit CLI

CloudSec Audit CLI is a Python-based tool for auditing AWS environments for common misconfigurations. It supports IAM, S3, EC2, security group, and Terraform audits. Designed to be modular, testable, and CI/CD friendly.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/cloudsec_audit.git
cd cloudsec_audit
```

## CI/CD Integration

To use CloudSec Audit in your CI pipeline:

1. Add your AWS credentials to your GitHub repo secrets.
2. Copy `.github/workflows/cloudsec_audit.yml` to your repo.
3. Adjust the `--check` argument to your desired module (e.g., `--check iam`).
