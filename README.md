# 🛡️ Digital Safety Guardian

> **A defensive cybersecurity platform for detecting social-engineering and digital-safety threats.**

Digital Safety Guardian (DSG) is an open-source cybersecurity project designed to help users identify suspicious messages and understand the security risks associated with social engineering, credential theft, payment requests, and account-based threats.

DSG analyzes submitted text, identifies security indicators, calculates a risk score, and returns an understandable assessment through a REST API.

---

## 🚨 The Problem

Social engineering remains one of the most effective ways attackers compromise individuals and organizations.

Attackers commonly use:

- Urgency and pressure
- Account suspension threats
- Fake security alerts
- OTP and verification-code requests
- Password requests
- Payment instructions
- Impersonation
- Fake customer-support messages
- Cryptocurrency recovery scams

The challenge is that many victims don't recognize these indicators until after they have responded.

**Digital Safety Guardian aims to provide an additional layer of awareness before a user takes a risky action.**

---

# 🎯 Project Goal

The long-term goal of DSG is to become a unified digital-safety platform capable of analyzing multiple forms of cyber risk.

The initial version focuses on **social-engineering message analysis**.

Future versions will expand into:

- Phishing and malicious URL analysis
- Scam detection
- Digital identity protection
- IoT security assessment
- Digital-asset and wallet safety
- AI-assisted threat analysis
- Security awareness education

---

# 🧠 How DSG Works

The current architecture is intentionally simple and explainable.

```text
                User Message
                     │
                     ▼
              FastAPI REST API
                     │
                     ▼
              Threat Detector
              (detector.py)
                     │
                     ▼
              Threat Findings
                     │
                     ▼
              Risk Engine
           (risk_engine.py)
                     │
                     ▼
             Risk Calculation
                     │
                     ▼
        ┌────────────┬────────────┐
        │            │            │
        ▼            ▼            ▼
    Risk Score   Risk Level    Findings
