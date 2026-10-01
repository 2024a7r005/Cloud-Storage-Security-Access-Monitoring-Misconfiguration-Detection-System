import boto3
import json
from moto import mock_aws


@mock_aws
def storage_security():

    s3 = boto3.client(
        "s3",
        region_name="ap-south-1"
    )

    # Secure bucket
    secure_bucket = "secure-corporate-bucket"

    s3.create_bucket(
        Bucket=secure_bucket,
        CreateBucketConfiguration={
            "LocationConstraint": "ap-south-1"
        }
    )

    # Encryption
    s3.put_bucket_encryption(
        Bucket=secure_bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }
            ]
        }
    )

    # Public access block
    s3.put_public_access_block(
        Bucket=secure_bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    )

    # Versioning
    s3.put_bucket_versioning(
        Bucket=secure_bucket,
        VersioningConfiguration={
            "Status": "Enabled"
        }
    )

    # Secure bucket policy
    secure_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789012:user/SecureUser"
                },
                "Action": ["s3:GetObject"],
                "Resource": f"arn:aws:s3:::{secure_bucket}/*"
            }
        ]
    }

    s3.put_bucket_policy(
        Bucket=secure_bucket,
        Policy=json.dumps(secure_policy)
    )

    # Insecure bucket
    insecure_bucket = "public-insecure-logs-bucket"

    s3.create_bucket(
        Bucket=insecure_bucket,
        CreateBucketConfiguration={
            "LocationConstraint": "ap-south-1"
        }
    )

    # Public bucket policy
    insecure_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{insecure_bucket}/*"
            }
        ]
    }

    s3.put_bucket_policy(
        Bucket=insecure_bucket,
        Policy=json.dumps(insecure_policy)
    )

    print("\n==========================================")
    print("       STORAGE SECURITY CHECK")
    print("==========================================")

    for bucket in s3.list_buckets()["Buckets"]:

        name = bucket["Name"]

        print(f"\n[+] Auditing Bucket: {name}")

        # Encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
            print("   Encryption: ENABLED [PASS]")
        except Exception:
            print("   Encryption: MISSING [HIGH RISK]")

        # Public access
        try:
            response = s3.get_public_access_block(
                Bucket=name
            )

            config = response["PublicAccessBlockConfiguration"]

            if (
                config["BlockPublicAcls"]
                and config["IgnorePublicAcls"]
                and config["BlockPublicPolicy"]
                and config["RestrictPublicBuckets"]
            ):
                print("   Public Access: BLOCKED [PASS]")
            else:
                print(
                    "   Public Access: NOT BLOCKED [HIGH RISK]"
                )

        except Exception:
            print(
                "   Public Access: NOT BLOCKED [HIGH RISK]"
            )

        # Versioning
        response = s3.get_bucket_versioning(
            Bucket=name
        )

        if response.get("Status") == "Enabled":
            print("   Versioning: ENABLED [PASS]")
        else:
            print(
                "   Versioning: DISABLED [MEDIUM RISK]"
            )

        # Bucket policy
        try:
            response = s3.get_bucket_policy(
                Bucket=name
            )

            policy = json.loads(
                response["Policy"]
            )

            public_policy = False

            for statement in policy.get("Statement", []):

                if (
                    statement.get("Effect") == "Allow"
                    and statement.get("Principal") == "*"
                ):
                    public_policy = True

            if public_policy:
                print(
                    "   Bucket Policy: PUBLIC ACCESS ALLOWED [HIGH RISK]"
                )
            else:
                print(
                    "   Bucket Policy: RESTRICTED [PASS]"
                )

        except Exception:
            print(
                "   Bucket Policy: NOT FOUND [MEDIUM RISK]"
            )


if __name__ == "__main__":
    storage_security()