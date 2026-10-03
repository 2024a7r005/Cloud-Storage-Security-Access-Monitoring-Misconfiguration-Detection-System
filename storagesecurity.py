import boto3
from moto import mock_aws


@mock_aws
def storage_security():
    s3 = boto3.client("s3", region_name="ap-south-1")

    secure_bucket = "secure-corporate-bucket"
    insecure_bucket = "public-insecure-logs-bucket"

    # Create test buckets
    s3.create_bucket(
        Bucket=secure_bucket,
        CreateBucketConfiguration={
            "LocationConstraint": "ap-south-1"
        }
    )

    s3.create_bucket(
        Bucket=insecure_bucket,
        CreateBucketConfiguration={
            "LocationConstraint": "ap-south-1"
        }
    )

    # -----------------------------
    # Secure bucket configuration
    # -----------------------------

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

    s3.put_public_access_block(
        Bucket=secure_bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    )

    s3.put_bucket_versioning(
        Bucket=secure_bucket,
        VersioningConfiguration={
            "Status": "Enabled"
        }
    )

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
        Policy=str(secure_policy).replace("'", '"')
    )

    # -----------------------------
    # Insecure bucket configuration
    # -----------------------------

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
        Policy=str(insecure_policy).replace("'", '"')
    )

    # -----------------------------
    # Security checks
    # -----------------------------

    security_results = []

    for bucket in [secure_bucket, insecure_bucket]:

        print("\n==========================================")
        print(f"       STORAGE SECURITY CHECK")
        print("==========================================")
        print(f"\n[+] Auditing Bucket: {bucket}")

        # Encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket)
            encryption_enabled = bool(encryption)
        except Exception:
            encryption_enabled = False

        # Public access
        try:
            public_access = s3.get_public_access_block(Bucket=bucket)

            config = public_access["PublicAccessBlockConfiguration"]

            public_access_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False)
            ])

        except Exception:
            public_access_blocked = False

        # Versioning
        versioning = s3.get_bucket_versioning(Bucket=bucket)

        versioning_enabled = (
            versioning.get("Status") == "Enabled"
        )

        # Bucket policy
        try:
            policy_response = s3.get_bucket_policy(Bucket=bucket)
            policy = policy_response["Policy"]

            public_policy = '"Principal": "*"' in policy

        except Exception:
            public_policy = False

        # -----------------------------
        # Display results
        # -----------------------------

        print(
            f"   Encryption: "
            f"{'ENABLED [PASS]' if encryption_enabled else 'DISABLED [HIGH]'}"
        )

        print(
            f"   Public Access: "
            f"{'BLOCKED [PASS]' if public_access_blocked else 'NOT BLOCKED [HIGH]'}"
        )

        print(
            f"   Versioning: "
            f"{'ENABLED [PASS]' if versioning_enabled else 'DISABLED [MEDIUM]'}"
        )

        print(
            f"   Bucket Policy: "
            f"{'PUBLIC [HIGH]' if public_policy else 'RESTRICTED [PASS]'}"
        )

        # -----------------------------
        # Store structured result
        # -----------------------------

        security_results.append({
            "Bucket": bucket,
            "Encryption": encryption_enabled,
            "PublicAccessBlocked": public_access_blocked,
            "Versioning": versioning_enabled,
            "PublicPolicy": public_policy
        })

    return security_results


if __name__ == "__main__":
    results = storage_security()