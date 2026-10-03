import pandas as pd


def access_monitoring():

    print("\n")
    print("==========================================")
    print("          ACCESS MONITORING")
    print("==========================================")

    activity_data = [
        {
            "User": "Alice",
            "Action": "GetObject",
            "Bucket": "secure-corporate-bucket",
            "Status": "Success"
        },
        {
            "User": "Bob",
            "Action": "PutObject",
            "Bucket": "secure-corporate-bucket",
            "Status": "Success"
        },
        {
            "User": "Unknown",
            "Action": "GetObject",
            "Bucket": "secure-corporate-bucket",
            "Status": "Failed"
        },
        {
            "User": "Unknown",
            "Action": "GetObject",
            "Bucket": "secure-corporate-bucket",
            "Status": "Failed"
        },
        {
            "User": "Unknown",
            "Action": "GetObject",
            "Bucket": "secure-corporate-bucket",
            "Status": "Failed"
        },
        {
            "User": "Alice",
            "Action": "DeleteObject",
            "Bucket": "secure-corporate-bucket",
            "Status": "Success"
        }
    ]

    activity_df = pd.DataFrame(activity_data)

    print("\nActivity Records:")
    print(activity_df.to_string(index=False))

    findings = []

    # Unknown user
    unknown_activity = activity_df[
        activity_df["User"] == "Unknown"
    ]

    if not unknown_activity.empty:
        findings.append(
            "HIGH: Access activity detected from an unknown user."
        )

    # Repeated failed attempts
    failed_activity = activity_df[
        activity_df["Status"] == "Failed"
    ]

    if len(failed_activity) >= 3:
        findings.append(
            "HIGH: Multiple failed access attempts detected."
        )

    # Delete activity
    delete_activity = activity_df[
        activity_df["Action"] == "DeleteObject"
    ]

    if not delete_activity.empty:
        findings.append(
            "MEDIUM: Object deletion activity detected."
        )

    print("\nAccess Monitoring Findings:")

    if findings:
        for finding in findings:
            print(f" - {finding}")
    else:
        print(
            " - No suspicious access activity detected."
        )

    return {
        "Activity": activity_df,
        "Findings": findings
    }


if __name__ == "__main__":
    access_monitoring()