# Cloud Security Baseline Drift Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Security-Defensive_Auditor-blue?style=flat" alt="Type">
  <img src="https://img.shields.io/badge/Status-Architectural_Showcase-success?style=flat" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python">
</p>

> 🔒 **Technical Showcase & Architecture Specification**  
> *This repository provides public architectural documentation, system specifications, and implementation summaries. Full production source code, internal test suites, and proprietary algorithms are maintained in a secure private repository.*

---

## 📌 Executive Summary

**Category**: Cloud Security & Compliance  
**Tech Stack**: `Python 3.10+ · JSON Schema · Cloud Governance · State Reconciler`  

Automated engine for comparing temporal cloud infrastructure snapshots and detecting unauthorized security baseline drift.

---

## 🎯 The Problem It Solves

Cloud infrastructure constantly changes as teams deploy resources. Unapproved modifications—such as disabled encryption, public exposure, disabled MFA, or disabled access logs—frequently go unnoticed, introducing critical vulnerabilities into production.

---

## ⚙️ How the Engine Works

The engine operates on normalized cloud resource state representations taken across distinct points in time:
1. **Snapshot Normalization & Indexing**: Ingests baseline (`before`) and current (`after`) cloud state snapshots, validating schema conformity and indexing unique resource identifiers.
2. **Resource Lifecycle Tracking**: Reconciles membership sets to flag unauthorized resource creation (`RESOURCE_ADDED`) or unexpected resource deletion (`RESOURCE_REMOVED`).
3. **Security Invariant Validation**: For each active resource, inspects critical security fields (`public`, `encrypted`, `logging_enabled`, `mfa_enabled`).
4. **Drift Classification & Severity Assignment**: When a state transitions to an unsafe posture, the engine tags it as `HIGH` severity `SECURITY_DRIFT` with before-and-after evidence.
5. **Actionable Remediation Generation**: Emits structured JSON findings pairing every drift event with targeted remediation guidelines.

---

## 🚀 Key Capabilities

- Detects unauthorized bucket and database public exposure transitions
- Identifies disabled cryptographic controls (at-rest and in-transit)
- Flags disabled audit logging and missing multi-factor authentication
- Generates audit-ready evidence payloads for compliance verification

---

## 🏗️ System Data Flow & Architecture

```
+-----------------------------------+
|  Target Input / Configuration    |
|  (JSON Snapshots / Policies)      |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  1. Schema Normalization Engine   |
|  Validates types & formats        |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  2. Core Analytical Pipeline      |
|  Heuristic rule evaluation,       |
|  invariant checks & drift diffs   |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  3. Risk Classification           |
|  Assigns severity: INFO / HIGH    |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  4. Structured Findings & Report  |
|  Root cause, evidence &           |
|  actionable remediation steps     |
+-----------------------------------+
```

---

## 📄 Findings Output Structure

The engine generates structured, machine-parsable JSON reports adhering to this standard audit schema:

```json
{
  "results": [
    {
      "resource": "resource-identifier",
      "severity": "HIGH",
      "check": "CHECK_IDENTIFIER",
      "detail": "Descriptive analysis of the identified security posture issue.",
      "remediation": "Actionable step-by-step guidance to restore compliant state.",
      "evidence": {
        "observed_field": "value",
        "required_policy": "enforced_policy"
      }
    }
  ],
  "count": 1,
  "scope": "Comprehensive defensive security audit"
}
```

---

## 🔒 Source Code & Enterprise Inquiries

To protect proprietary intellectual property and client operational security:
* **Public Repository**: Contains comprehensive architecture specifications, schemas, and design overviews.
* **Private Repository**: Contains the complete production implementation, continuous integration pipelines, and full regression test suites.

For architectural questions or enterprise inquiries, connect via [LinkedIn](https://www.linkedin.com/in/karthikeyansubramaniam04/) or visit the [Portfolio Site](https://karthikeyansubramaniyam.github.io).
