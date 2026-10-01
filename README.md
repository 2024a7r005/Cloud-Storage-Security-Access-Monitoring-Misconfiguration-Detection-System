# Cloud Storage Security, Access Monitoring & Misconfiguration Detection System

## Project Overview

This project proposes a security system for cloud storage that focuses on identifying insecure storage configurations, monitoring access activity, and detecting common security misconfigurations.

The system is designed around Amazon S3 as the cloud-storage environment and uses Python-based security modules with a rule-based analysis approach.

The current prototype implements the core security-analysis modules and uses a simulated S3 environment for development and testing.

---

## Problem Statement

Cloud storage environments can be exposed to security risks due to incorrect access permissions, public exposure, missing security controls, and suspicious access activity.

The objective of this project is to develop a lightweight security system that can:

- Assess important cloud-storage security configurations.
- Monitor storage access activity.
- Detect common security misconfigurations.
- Classify identified issues according to risk.
- Provide recommendations for improving the security configuration.

---

## Proposed System

The system is divided into three main security modules:

### 1. Storage Security

**File:** `storage_security.py`

This module checks important S3 security configurations:

- Server-side encryption
- Public-access blocking
- Bucket versioning
- Bucket policies

The prototype uses test bucket configurations containing both secure and intentionally insecure settings to demonstrate the security checks.

### 2. Access Monitoring

**File:** `access_monitoring.py`

This module analyzes cloud-storage access activity using Pandas.

The current implementation identifies activities such as:

- Unknown-user access
- Multiple failed access attempts
- Object deletion activity

Rule-based conditions are used to identify potentially risky events.

### 3. Misconfiguration Detection

**File:** `misconfiguration_detection.py`

This module evaluates the security results and identifies configuration weaknesses.

Current checks include:

- Missing encryption
- Public access not blocked
- Disabled versioning
- Public bucket policies

The detected issues are assigned risk levels and corresponding security recommendations.

---

## System Architecture

```text
              Cloud Storage
               (S3 / Mock S3)
                    |
        +-----------+-----------+
        |                       |
        v                       v
 Storage Security        Access Monitoring
        |                       |
        +-----------+-----------+
                    |
                    v
        Misconfiguration Detection
                    |
                    v
          Risk Classification
                    |
                    v
        Security Recommendations
