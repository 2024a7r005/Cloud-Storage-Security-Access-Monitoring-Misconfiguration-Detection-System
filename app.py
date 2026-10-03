import streamlit as st
import pandas as pd

from misconfiguration_detection import misconfiguration_detection
from database import create_database, save_findings


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

create_database()


# ---------------------------------------------------------
# PAGE SETTINGS
# ---------------------------------------------------------

st.set_page_config(
    page_title="Cloud Storage Security",
    page_icon="🔐",
    layout="wide"
)


# ---------------------------------------------------------
# TITLE
# ---------------------------------------------------------

st.title("Cloud Storage Security")

st.write(
    "A simple security assessment system for cloud storage. "
    "Upload security data, analyze it, and identify security risks."
)


# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------

st.sidebar.title("Cloud Security")

page = st.sidebar.radio(
    "Application",
    [
        "Dashboard",
        "Upload & Analyze",
        "Cloud Storage Security",
        "Access Monitoring",
        "Security Findings",
        "Recommendations"
    ]
)


# ---------------------------------------------------------
# SESSION STORAGE
# ---------------------------------------------------------

if "security_results" not in st.session_state:
    st.session_state.security_results = []

if "access_data" not in st.session_state:
    st.session_state.access_data = pd.DataFrame()

if "findings" not in st.session_state:
    st.session_state.findings = []

if "access_findings" not in st.session_state:
    st.session_state.access_findings = []

if "recommendations" not in st.session_state:
    st.session_state.recommendations = []

if "overall_risk" not in st.session_state:
    st.session_state.overall_risk = "No Assessment"


# =========================================================
# DASHBOARD
# =========================================================

if page == "Dashboard":

    st.header("Security Dashboard")

    if not st.session_state.security_results:

        st.info(
            "No security assessment has been performed yet. "
            "Go to 'Upload & Analyze' and upload a security data CSV file."
        )

    else:

        security_results = st.session_state.security_results
        findings = st.session_state.findings
        access_findings = st.session_state.access_findings

        high_count = sum(
            1 for finding in findings
            if finding["Severity"] == "HIGH"
        )

        medium_count = sum(
            1 for finding in findings
            if finding["Severity"] == "MEDIUM"
        )

        access_alerts = len(access_findings)

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Buckets Assessed",
                len(security_results)
            )

        with col2:
            st.metric(
                "High Risk Findings",
                high_count
            )

        with col3:
            st.metric(
                "Medium Risk Findings",
                medium_count
            )

        with col4:
            st.metric(
                "Access Alerts",
                access_alerts
            )

        st.subheader("Overall Security Risk")

        risk = st.session_state.overall_risk

        if risk == "HIGH":
            st.error("HIGH RISK")

        elif risk == "MEDIUM":
            st.warning("MEDIUM RISK")

        elif risk == "LOW":
            st.success("LOW RISK")

        else:
            st.info("No Assessment")


# =========================================================
# UPLOAD & ANALYZE
# =========================================================

elif page == "Upload & Analyze":

    st.header("Upload Security Data")

    st.write(
        "Upload a CSV file containing cloud-storage "
        "configuration and access activity."
    )

    uploaded_file = st.file_uploader(
        "Choose a CSV file",
        type=["csv"]
    )

    if uploaded_file is not None:

        try:

            data = pd.read_csv(uploaded_file)

            st.subheader("Uploaded Data")

            st.dataframe(
                data,
                use_container_width=True,
                hide_index=True
            )

            required_columns = [
                "Bucket",
                "Encryption",
                "PublicAccessBlocked",
                "Versioning",
                "PublicPolicy",
                "User",
                "Action",
                "Status"
            ]

            missing_columns = [
                column
                for column in required_columns
                if column not in data.columns
            ]

            if missing_columns:

                st.error(
                    "Missing columns: "
                    + ", ".join(missing_columns)
                )

            else:

                if st.button(
                    "Analyze Security Data",
                    type="primary"
                ):

                    # -------------------------------------
                    # STORAGE SECURITY ANALYSIS
                    # -------------------------------------

                    security_results = []

                    for bucket in data["Bucket"].unique():

                        bucket_data = data[
                            data["Bucket"] == bucket
                        ].iloc[0]

                        security_results.append({
                            "Bucket": bucket,

                            "Encryption":
                                str(
                                    bucket_data["Encryption"]
                                ).lower() == "yes",

                            "PublicAccessBlocked":
                                str(
                                    bucket_data[
                                        "PublicAccessBlocked"
                                    ]
                                ).lower() == "yes",

                            "Versioning":
                                str(
                                    bucket_data["Versioning"]
                                ).lower() == "yes",

                            "PublicPolicy":
                                str(
                                    bucket_data["PublicPolicy"]
                                ).lower() == "yes"
                        })

                    # -------------------------------------
                    # MISCONFIGURATION ANALYSIS
                    # -------------------------------------

                    results = misconfiguration_detection(
                        security_results
                    )

                    # -------------------------------------
                    # ACCESS DATA
                    # -------------------------------------

                    access_data = data[
                        [
                            "User",
                            "Action",
                            "Bucket",
                            "Status"
                        ]
                    ].copy()

                    # -------------------------------------
                    # ACCESS FINDINGS
                    # -------------------------------------

                    access_findings = []

                    unknown_activity = access_data[
                        access_data["User"].astype(str).str.lower()
                        == "unknown"
                    ]

                    if not unknown_activity.empty:

                        access_findings.append(
                            "HIGH: Access activity detected from an unknown user."
                        )

                    failed_activity = access_data[
                        access_data["Status"].astype(str).str.lower()
                        == "failed"
                    ]

                    if len(failed_activity) >= 3:

                        access_findings.append(
                            "HIGH: Multiple failed access attempts detected."
                        )

                    delete_activity = access_data[
                        access_data["Action"].astype(str).str.lower()
                        == "deleteobject"
                    ]

                    if not delete_activity.empty:

                        access_findings.append(
                            "MEDIUM: Object deletion activity detected."
                        )

                    # -------------------------------------
                    # SAVE RESULTS
                    # -------------------------------------

                    st.session_state.security_results = (
                        security_results
                    )

                    st.session_state.access_data = (
                        access_data
                    )

                    st.session_state.findings = (
                        results["Findings"]
                    )

                    st.session_state.access_findings = (
                        access_findings
                    )

                    st.session_state.recommendations = (
                        results["Recommendations"]
                    )

                    st.session_state.overall_risk = (
                        results["OverallRisk"]
                    )

                    # -------------------------------------
                    # SAVE TO SQLITE
                    # -------------------------------------

                    save_findings(
                        results["Findings"],
                        results["Recommendations"],
                        results["OverallRisk"]
                    )

                    st.success(
                        "Security analysis completed successfully."
                    )

                    # -------------------------------------
                    # SHOW RESULT
                    # -------------------------------------

                    st.subheader("Assessment Result")

                    if results["OverallRisk"] == "HIGH":

                        st.error("HIGH RISK")

                    elif results["OverallRisk"] == "MEDIUM":

                        st.warning("MEDIUM RISK")

                    else:

                        st.success("LOW RISK")

                    st.write(
                        f"Buckets analyzed: "
                        f"**{len(security_results)}**"
                    )

                    st.write(
                        f"Misconfiguration findings: "
                        f"**{len(results['Findings'])}**"
                    )

                    st.write(
                        f"Access alerts: "
                        f"**{len(access_findings)}**"
                    )

        except Exception as error:

            st.error(
                f"Unable to analyze the file: {error}"
            )


# =========================================================
# CLOUD STORAGE SECURITY
# =========================================================

elif page == "Cloud Storage Security":

    st.header("Cloud Storage Security")

    security_results = st.session_state.security_results

    if not security_results:

        st.info(
            "No storage security assessment available. "
            "Upload and analyze a CSV file first."
        )

    else:

        st.write(
            "Security configuration detected for the assessed cloud buckets."
        )

        security_df = pd.DataFrame(
            security_results
        )

        st.dataframe(
            security_df,
            use_container_width=True,
            hide_index=True
        )

        st.subheader("Security Configuration")

        for result in security_results:

            st.write(
                f"**{result['Bucket']}**"
            )

            col1, col2, col3, col4 = st.columns(4)

            with col1:

                if result["Encryption"]:
                    st.success("Encryption: Enabled")

                else:
                    st.error("Encryption: Disabled")

            with col2:

                if result["PublicAccessBlocked"]:
                    st.success("Public Access: Blocked")

                else:
                    st.error("Public Access: Not Blocked")

            with col3:

                if result["Versioning"]:
                    st.success("Versioning: Enabled")

                else:
                    st.warning("Versioning: Disabled")

            with col4:

                if result["PublicPolicy"]:
                    st.error("Public Policy: Detected")

                else:
                    st.success("Public Policy: Not Detected")


# =========================================================
# ACCESS MONITORING
# =========================================================

elif page == "Access Monitoring":

    st.header("Access Monitoring")

    access_data = st.session_state.access_data
    access_findings = st.session_state.access_findings

    if access_data.empty:

        st.info(
            "No access activity data available. "
            "Upload and analyze a CSV file first."
        )

    else:

        st.subheader("Access Activity")

        st.dataframe(
            access_data,
            use_container_width=True,
            hide_index=True
        )

        st.subheader("Access Alerts")

        if access_findings:

            for finding in access_findings:

                if finding.startswith("HIGH"):
                    st.error(finding)

                else:
                    st.warning(finding)

        else:

            st.success(
                "No suspicious access activity detected."
            )


# =========================================================
# SECURITY FINDINGS
# =========================================================

elif page == "Security Findings":

    st.header("Security Findings")

    findings = st.session_state.findings

    if not findings:

        st.info(
            "No assessment results available. "
            "Upload and analyze a CSV file first."
        )

    else:

        findings_df = pd.DataFrame(
            findings
        )

        st.subheader("Storage Misconfigurations")

        st.dataframe(
            findings_df,
            use_container_width=True,
            hide_index=True
        )

        st.subheader("Access Monitoring")

        access_findings = st.session_state.access_findings

        if access_findings:

            for finding in access_findings:

                if finding.startswith("HIGH"):
                    st.error(finding)

                else:
                    st.warning(finding)

        else:

            st.success(
                "No suspicious access activity detected."
            )


# =========================================================
# RECOMMENDATIONS
# =========================================================

elif page == "Recommendations":

    st.header("Security Recommendations")

    recommendations = (
        st.session_state.recommendations
    )

    if not recommendations:

        st.info(
            "No recommendations available. "
            "Upload and analyze a CSV file first."
        )

    else:

        for recommendation in recommendations:

            st.info(
                f"{recommendation['Bucket']}: "
                f"{recommendation['Recommendation']}"
            )


# ---------------------------------------------------------
# FOOTER
# ---------------------------------------------------------

st.sidebar.divider()

st.sidebar.caption(
    "Cloud Storage Security System"
)