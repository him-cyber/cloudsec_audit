import boto3

def get_boto3_session(profile=None):
    return boto3.Session(profile_name=profile) if profile else boto3.Session()
