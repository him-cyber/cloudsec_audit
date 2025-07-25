import boto3
import os
import logging

def get_boto3_session(profile=None):
    is_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")

    if not region:
        if os.environ.get("ENV") == "prod":
            raise EnvironmentError(
                "AWS region not specified. Set AWS_REGION or AWS_DEFAULT_REGION before running this tool in production."
            )
        else:
            region = "us-east-1"
            logging.warning("No AWS region specified. Defaulting to us-east-1.")

    if is_ci:
        # GitHub Actions uses environment variables set via secrets
        return boto3.Session(region_name=region)
    return boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
