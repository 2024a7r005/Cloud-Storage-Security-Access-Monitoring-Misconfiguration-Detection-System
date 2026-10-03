import sqlite3


DATABASE = "security_results.db"


def create_database():
    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bucket TEXT,
            risk TEXT,
            issue TEXT,
            recommendation TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_findings(findings, recommendations, overall_risk):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    for finding in findings:

        bucket = finding["Bucket"]
        issue = finding["Issue"]
        severity = finding["Severity"]

        recommendation = ""

        for item in recommendations:
            if item["Bucket"] == bucket:
                recommendation = item["Recommendation"]
                break

        cursor.execute("""
            INSERT INTO scan_history
            (bucket, risk, issue, recommendation)
            VALUES (?, ?, ?, ?)
        """, (
            bucket,
            severity,
            issue,
            recommendation
        ))

    conn.commit()
    conn.close()


def get_scan_history():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, bucket, risk, issue, recommendation
        FROM scan_history
        ORDER BY id DESC
    """)

    results = cursor.fetchall()

    conn.close()

    return results