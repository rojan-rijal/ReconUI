import boto3, sys
s3 = boto3.client('s3')
s3.create_bucket(Bucket=sys.argv[1])
