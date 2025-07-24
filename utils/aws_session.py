import boto3
import os

def get_boto3_session(profile=None):
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return boto3.Session()
    return boto3.Session(profile_name=profile) if profile else boto3.Session()
