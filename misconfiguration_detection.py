def misconfiguration_detection(security_results):

    findings = []
    recommendations = []

    for result in security_results:

        bucket = result["Bucket"]

        # Encryption check
        if not result["Encryption"]:
            findings.append({
                "Bucket": bucket,
                "Severity": "HIGH",
                "Issue": "Bucket encryption is disabled"
            })

            recommendations.append({
                "Bucket": bucket,
                "Recommendation": "Enable server-side encryption"
            })

        # Public access check
        if not result["PublicAccessBlocked"]:
            findings.append({
                "Bucket": bucket,
                "Severity": "HIGH",
                "Issue": "Public access is not blocked"
            })

            recommendations.append({
                "Bucket": bucket,
                "Recommendation": "Enable all S3 public access block settings"
            })

        # Versioning check
        if not result["Versioning"]:
            findings.append({
                "Bucket": bucket,
                "Severity": "MEDIUM",
                "Issue": "Bucket versioning is disabled"
            })

            recommendations.append({
                "Bucket": bucket,
                "Recommendation": "Enable bucket versioning"
            })

        # Bucket policy check
        if result["PublicPolicy"]:
            findings.append({
                "Bucket": bucket,
                "Severity": "HIGH",
                "Issue": "Bucket policy allows public access"
            })

            recommendations.append({
                "Bucket": bucket,
                "Recommendation": "Restrict bucket policy to authorized users"
            })

    # Calculate overall risk
    severities = [finding["Severity"] for finding in findings]

    if "HIGH" in severities:
        overall_risk = "HIGH"
    elif "MEDIUM" in severities:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    print("\n==========================================")
    print("       MISCONFIGURATION DETECTION")
    print("==========================================")

    print(f"\nOverall Risk: {overall_risk}")

    print("\n--- Findings ---")

    if findings:
        for finding in findings:
            print(
                f"[{finding['Severity']}] "
                f"{finding['Bucket']} - "
                f"{finding['Issue']}"
            )
    else:
        print("No security misconfigurations detected.")

    print("\n--- Recommendations ---")

    if recommendations:
        for recommendation in recommendations:
            print(
                f"{recommendation['Bucket']}: "
                f"{recommendation['Recommendation']}"
            )
    else:
        print("No recommendations required.")

    return {
        "OverallRisk": overall_risk,
        "Findings": findings,
        "Recommendations": recommendations
    }


# Run this file directly
if __name__ == "__main__":

    from storagesecurity import storage_security

    security_results = storage_security()

    misconfiguration_detection(security_results)