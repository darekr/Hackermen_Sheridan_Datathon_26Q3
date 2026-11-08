# Sheridan Datathon 26Q3: Empirical Analysis & Key Threat Findings

**Project:** Hackermen Sheridan Datathon 26Q3  
**Foundation Model:** IBM Granite 4:3B & Granite-Code:3B  
**Target Dataset:** Scoreboard 2026 (72,670 evaluated CVEs) + Historical Telemetry (2024–2025)

---

## Executive Summary

Using the **Granite CVE Analyzer** and **Multi-CSV Comparative Agent**, we performed an end-to-end audit across 72,670 target vulnerabilities in `scoreboard_2026.csv`, correlating them with:
- **CVSS 3.x Base Exploitability & Severity**
- **EPSS Version-Aware Telemetry** (discounting pre-v4 scores at `0.6x` vs. EPSS v4 at `1.0x`)
- **Real-World Attack Plane Mapping** across 3.15 million software records in `affected_products.csv`
- **CISA KEV Catalog & Weaponization Feeds** (Metasploit, ExploitDB, GitHub PoCs)

This report highlights empirical patterns uncovered in the **Top 500 High-Threat Vulnerabilities** and the **Unpublished / Deferred Pool**.

---

## 1. Real-World Attack Plane Distribution

Out of the Top 500 highest-threat vulnerabilities, the primary attack planes are distributed as follows:

| Attack Plane Category | Count in Top 500 | Percentage | Exposure Vector |
| :--- | :---: | :---: | :--- |
| **Core Operating System & Kernel** | **313** | **62.6%** | Remotely Exposed via Network Services |
| **Distributed Software Ecosystem** | **149** | **29.8%** | Third-party dependencies & libraries |
| **Enterprise Edge & Network Infrastructure** | **26** | **5.2%** | Firewalls, VPN gateways, routers, switches |
| **Web Servers & Cloud Applications** | **10** | **2.0%** | Web frameworks, WAFs, load balancers |
| **Core Operating System (Locally Constrained)** | **2** | **0.4%** | Privilege escalation vectors |

> [!IMPORTANT]
> **Key Insight:** Over **62% of high-threat exploits directly compromise core operating systems and kernel subsystems**, primarily driven by network-accessible services in enterprise environments.

---

## 2. Most Prevalent Weakness Types (CWE Breakdown)

Memory corruption and injection remain the overwhelming primary root causes for high-threat exploits:

```
CWE-122 (Heap-based Buffer Overflow)  ████████████████████████ 66
CWE-416 (Use After Free)             ███████████████████████ 64
CWE-787 (Out-of-bounds Write)        ████████ 21
CWE-20  (Improper Input Validation)  ██████ 17
CWE-78  (OS Command Injection)       ██████ 17
```

1. **CWE-122 (Heap-based Buffer Overflow - 66 CVEs)**: Widely leveraged for remote code execution (RCE) in network demons.
2. **CWE-416 (Use After Free - 64 CVEs)**: Dominant in client browser endpoints (Chrome, Safari) and kernel memory management.
3. **CWE-787 (Out-of-bounds Write - 21 CVEs)**: Key driver for high CVSS (9.8) critical vulnerabilities.
4. **CWE-78 & CWE-77 (Command Injection - 17+ CVEs)**: Characterized by the single highest composite risk scores (e.g., `CVE-2026-8037` with score **80.59** and EPSS **0.8479**).

---

## 3. Most Targeted Vendor Ecosystems

Cross-referencing `affected_products.csv` revealed the vendors with the largest exposure footprint:

| Vendor | High-Threat CVEs | Primary Affected Products |
| :--- | :---: | :--- |
| **Microsoft** | **296** | Windows 10/11, Windows Server, Edge, Office |
| **Linux Foundation** | **137** | Linux Kernel, Coreutils, Systemd |
| **Apple** | **129** | macOS, iOS, WebKit, Safari |
| **Google** | **67** | Chromium, Android OS, Pixel Firmware |
| **Adobe** | **53** | Acrobat, Photoshop, Creative Cloud Components |

---

## 4. EPSS v3 vs. EPSS v4 Telemetry Findings

- **Release Policy Impact**: Applying the **early 2025 EPSS v4 release cutoff** properly stabilized predictive accuracy by discounting pre-v4 scores (pre-`2025-03`) at `0.6x`.
- **Active Telemetry Coverage**: In `top500.csv`, **498 out of 500 entries (99.6%)** possess active EPSS probability data in the 2026 scoreboard.
- **Zero-EPSS Indicators**: Exactly **2 vulnerabilities** in the Top 500 had `EPSS = 0.0000`, properly flagged as **"No information available in scoreboard"** (e.g. `CVE-2026-24148`), where threat score is driven by high CVSS and multi-vendor Attack Matrix Size.

---

## 5. Unpublished & Deferred Vulnerabilities (Pre-Analysis Pool)

Our cross-correlation between `vulnerabilities.csv` and `scoreboard_2026.csv` surfaced **36,287 vulnerabilities** that are unanalyzed or deferred by NVD:
- **`Deferred`**: 27,207 CVEs
- **`Awaiting Analysis`**: 5,108 CVEs
- **`Received`**: 3,614 CVEs
- **`Undergoing Analysis`**: 358 CVEs

### High-Risk Deferred Targets Identified:
1. **`CVE-2022-25369`** (Status: `Deferred`, CVSS: **9.8**, EPSS: **0.6350**): Unauthenticated admin creation in Dynamicweb.
2. **`CVE-2024-45257`** (Status: `Awaiting Analysis`, CVSS: **7.3**, EPSS: **0.5955**): Command Injection in BYOB (Build Your Own Botnet) payload builder.
3. **`CVE-2026-27771`** (Status: `Deferred`, CVSS: **8.2**, EPSS: **0.4307**): Composer package permission bypass in Gitea.

> [!TIP]
> By tracking these in the separate section of [`dashboard.html`](file:///c:/Users/User/Hackermen_Sheridan_Datathon_26Q3/Hackermen_Sheridan_Datathon_26Q3/dashboard.html), security teams gain early zero-day exposure visibility months before formal NVD triage completes.

---

## 6. Recommendations for Security Operations

1. **Prioritize Edge Infrastructure & Command Injection**: Vulnerabilities with `CWE-77/78` and EPSS > 0.5 (such as `CVE-2026-8037`) should be patched within 24 hours.
2. **Automate Version-Weighted EPSS in SIEM Pipelines**: Use the `epss_weighting` module to prevent older EPSS scores from polluting modern vulnerability risk rankings.
3. **Monitor the Pre-Analysis Pool**: Ingest NVD `Deferred` entries with high EPSS directly into threat hunting routines.

