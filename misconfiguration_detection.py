def misconfiguration_detection():

    print("\n")
    print("==========================================")
    print("      MISCONFIGURATION DETECTION")
    print("==========================================")

    # Results obtained from the storage-security checks
    security_results = [
        {
            "Bucket": "secure-corporate-bucket",
            "Encryption": True,
            "PublicAccessBlocked": True,
            "Versioning": True,
            "PublicPolicy": False
        },
        {
            "Bucket": "public-insecure-logs-bucket",
            "Encryption": False,
            "PublicAccessBlocked": False,
            "Versioning": False,
            "PublicPolicy": True
        }
    ]

    for bucket in security_results:

        name = bucket["Bucket"]

        findings = []
        recommendations = []
        risks = []

        print(f"\n[+] Checking: {name}")

        # Encryption
        if not bucket["Encryption"]:

            findings.append(
                "Encryption is missing"
            )

            recommendations.append(
                "Enable server-side encryption"
            )

            risks.append("HIGH")

        # Public access
        if not bucket["PublicAccessBlocked"]:

            findings.append(
                "Public access is not completely blocked"
            )

            recommendations.append(
                "Enable all S3 public access block settings"
            )

            risks.append("HIGH")

        # Versioning
        if not bucket["Versioning"]:

            findings.append(
                "Bucket versioning is disabled"
            )

            recommendations.append(
                "Enable bucket versioning"
            )

            risks.append("MEDIUM")

        # Public policy
        if bucket["PublicPolicy"]:

            findings.append(
                "Bucket policy allows public access"
            )

            recommendations.append(
                "Restrict bucket policy to authorized users"
            )

            risks.append("HIGH")

        # Overall risk
        if "HIGH" in risks:
            overall_risk = "HIGH"

        elif "MEDIUM" in risks:
            overall_risk = "MEDIUM"

        else:
            overall_risk = "LOW"

        print("\n   --- Security Assessment ---")
        print(f"   Overall Risk: {overall_risk}")

        print("\n   Findings:")

        if findings:
            for finding in findings:
                print(f"   - {finding}")
        else:
            print(
                "   - No security misconfigurations detected"
            )

        print("\n   Recommendations:")

        if recommendations:
            for recommendation in recommendations:
                print(f"   - {recommendation}")
        else:
            print(
                "   - No corrective action required"
            )


if __name__ == "__main__":
    misconfiguration_detection()