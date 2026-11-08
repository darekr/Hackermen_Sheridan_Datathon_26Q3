# Hackermen Sheridan Datathon 26Q3: Leak-Free Granite CVE Predictive Intelligence

An end-to-end, **100% leak-free** cyber threat intelligence and predictive vulnerability ranking platform built for the **Sheridan Datathon 26Q3**. Powered by **scikit-learn HistGradientBoosting**, an **auditable domain-weighted formula**, **TF-IDF + SVD semantic description embeddings**, and **IBM Granite 4:3B (`granite4:3b`)**, this system predicts which non-KEV vulnerabilities will be added to the CISA Known Exploited Vulnerabilities (KEV) catalog in the future — using **only information strictly available at the snapshot month**.

---

## 🛡️ The 4-Fix Leak-Free Architecture (`Granite_CVE_Analyzer/leak_free_model.py`)

### Fix 1: Stop Using Columns That Give the Answer Away (Data Leakage Prevention)
NIST/NVD enriches CVEs *after* they become high-profile or enter CISA KEV. Using post-hoc NVD fields leaks the answer key. We audited every column across all tables:

| Column / Source | Policy | Justification |
| :--- | :---: | :--- |
| `epss`, `is_epss_v4` (`snapshot_month >= 2025-03`) | **SAFE (Used)** | Snapshot-time probability and regime indicator for the March 2025 EPSS v4 release. |
| `nuclei`, `metasploit`, `exploitdb`, `poc_github` | **SAFE (Used)** | Public exploit & scanner templates observed at `snapshot_month`. |
| `description` & `assigner` (`vulnerabilities.csv`) | **SAFE (Used)** | Written by the CNA at publication time. Used to extract vendor, product, edge/appliance flags, unauthenticated RCE/auth-bypass, and semantic similarity to strictly prior KEVs. |
| `known_exploited.csv` (`date_added <= snapshot_month`) | **SAFE (Used)** | Strictly filtered to KEV entries added **on or before** `snapshot_month` to compute `vendor_prior_kev_count`, `vendor_prior_ransom_count`, and `assigner_prior_kev_count`. |
| `cvss3_score` (`cvss3_source != 'nvd@nist.gov'`) | **SAFE (Optional)** | Vendor/CNA or CISA CVSS provided at publication time. We also evaluate a **Strict No-CVSS** variant that drops CVSS completely. |
| `affected_products.csv` & `n_affected_cpes` | **UNSAFE (Dropped)** | Populated post-hoc by NIST analysts after exploitation. Replaced by description vendor extraction + strictly prior KEV counts. |
| `nvd_status` (`Analyzed` vs `Deferred` / `Awaiting`) | **UNSAFE (Dropped)** | Directly reflects whether NIST prioritized analyzing the CVE after disclosure. |
| `cvss3_score` (`cvss3_source == 'nvd@nist.gov'`) | **UNSAFE (Dropped)** | 196,952 post-hoc NIST scores and blank-score backlog patterns. |
| `references.csv` & `n_references` | **UNSAFE (Dropped)** | Accumulates post-disclosure advisory links and CISA KEV references over time. |

---

### Fix 2: Test Our Method on the Past (2024–2025 Out-of-Time Backtesting)
We rebuilt the exact scoreboard task on historical 2024–2025 data (`87,020` CVEs with `in_kev == 0` at their publication snapshot month, after excluding `62` pre-publication KEV anomalies where `date_added < published` and recovering `4,930` CVEs affected by the February 2025 missing-snapshot drop). Always training on older months and testing on newer unseen months (`91` future KEV additions across 5 test periods):

| Out-of-Time Test Period | Train Months | Test Pool | Future KEVs | `CVSS-First` | `EPSS-First` | `Exploit-then-EPSS` | `Readable Score` (Ours) | `Our Model` (GBDT+Readable) | `Strict No-CVSS` (Ours) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **2024-Q3 (Jul–Sep 2024)** | `2024-01..06` | 8,440 | 18 | 0 *(0)* | 3 *(2)* | 6 *(3)* | 8 *(5)* | **9 *(4)*** | **9 *(4)*** |
| **2024-Q4 (Oct–Dec 2024)** | `2024-01..09` | 11,000 | 21 | 0 *(0)* | 2 *(2)* | 5 *(3)* | 5 *(3)* | **7 *(5)*** | **7 *(5)*** |
| **2025-Q1 (Jan–Mar 2025, v4 Shift)** | `2024-01..12` | 12,139 | 18 | 3 *(1)* | 7 *(3)* | 6 *(3)* | 7 *(4)* | **13 *(5)*** | **13 *(5)*** |
| **2025-Q2 (Apr–Jun 2025, Post-v4)** | `2024-01..25-03` | 11,942 | 17 | 2 *(2)* | 9 *(6)* | 12 *(9)* | 12 *(10)* | **12 *(10)*** | **12 *(11)*** |
| **2025-H2 (Jul–Dec 2025, Latest)** | `2024-01..25-06` | 23,688 | 17 | 2 *(1)* | 3 *(2)* | 6 *(5)* | 7 *(5)* | **7 *(6)*** | **7 *(6)*** |
| **SUM OF PER-PERIOD TOP-500 *(Scaled)*** | — | **67,209** | **91** | **7 *(4)*** | **24 *(15)*** | **35 *(23)*** | **39 *(27)*** | **48 *(30)*** | **48 *(31)*** |
| **POOLED OUT-OF-TIME TOP-500** | — | **67,209** | **91** | **4** | **14** | **24** | **29** | **28** | **28** |

Our models match or beat every baseline in every period (2025-Q2 is a raw tie with Exploit-then-EPSS). The readable-formula weights were adjusted once after an earlier run of this backtest, so these numbers are somewhat optimistic; see the caveat in `DATATHON_ANALYSIS_FINDINGS.md`.

---

### Fix 3: Stop Granite Making Things Up (Anti-Hallucination & Grounded Drivers)
- **Strict Prediction Framing**: Prompts and deterministic fallbacks never claim a vulnerability is `"actively exploited"` or `"exploited in the wild"`.
- **Post-Check Verifier (`verify_and_sanitize_explanation`)**: Scans every Granite output for forbidden phrases and verifies that any decimal numbers match the exact input row.
- **Explicit Ranking Drivers**: Every row in `top500.csv` and `all_cves_assessed.csv` states the exact verified reasons it was ranked highly (e.g., `vendor 'progress' has 8 prior KEV entries before snapshot (4 tied to ransomware); internet-facing edge/network target; RCE + command injection; Nuclei template + GitHub PoC; EPSS v4 = 0.84793; description similarity 0.93 to prior KEV CVE-2019-7256`).

---

### Fix 4: Use Granite & NLP Embeddings for More Than Summaries
1. **Semantic Description Similarity (`TfidfVectorizer` + 48-dim `TruncatedSVD`)**: Embeds all CVE descriptions and computes cosine similarity against KEV descriptions added **strictly before** `snapshot_month` (`prior_kev_sim_max`, `prior_kev_sim_top5`, and `nearest_prior_kev_cve`).
2. **Structured JSON Extraction & Disk Caching (`Granite_CVE_Analyzer/granite_cache.json`)**: Queries local `granite4:3b` in structured JSON mode (`vendor`, `product`, `internet_facing`, `attack_type`, `explanation`) and caches every response on disk so no CVE is ever queried twice.

---

## 📐 Auditable Scoring Formulation

Our final score combines the out-of-time calibrated `HistGradientBoostingClassifier` probability ($P_{\text{GBDT}}$) with an auditable 100-point `Readable Leak-Free Score` ($S_{\text{readable}}$):

$$\text{Predicted KEV Risk Score} = 40.0 \times P_{\text{GBDT}}(\mathbf{x}_t) + 0.60 \times S_{\text{readable}}(\mathbf{x}_t)$$

Where $S_{\text{readable}}(\mathbf{x}_t) \in [0, 100]$ is composed of strictly pre-snapshot signals:
- **Snapshot EPSS & Regime Synergy (up to 36 pts)**: Concave transform of `epss` calibrated with `is_epss_v4` + `epss_x_exploit`.
- **Snapshot Public Exploit Artifacts (up to 34 pts)**: `has_any_exploit` (+13.0), `nuclei` (+8.5), `metasploit` (+7.5), `exploitdb` (+4.5), `poc_github` (+4.5).
- **Strictly Prior Vendor & Assigner KEV History (up to 14 pts)**: Log-scaled counts of KEV and ransomware-linked KEV entries for the extracted vendor/CNA with `date_added <= end_of_snapshot_month`.
- **Description Edge Appliance & Unauthenticated RCE/Bypass (up to 10 pts)**: Extracted from `description` text (`is_edge_appliance`, `is_unauthenticated`, `high_risk_attack_type`).
- **Semantic Description Similarity to Prior KEVs (up to 4 pts)**: Top-5 mean cosine similarity to strictly prior KEV descriptions.
- **Vendor/CNA CVSS (up to 2 pts, or 0 pts in Strict No-CVSS mode)**: Used only when `cvss3_source != 'nvd@nist.gov'`.

---

## 🚀 Quick Start

1. **Run the Full Leak-Free Backtest, Model Training, and 72,670-CVE Scoring Pipeline**:
   ```powershell
   python Granite_CVE_Analyzer/leak_free_model.py
   ```
   Outputs:
   - `top500.csv` (Top 500 predicted KEV candidates with verified explanations)
   - `all_cves_assessed.csv` (All 72,670 scoreboard CVEs scored and ranked)
   - `Granite_CVE_Analyzer/backtest_results.json` (Out-of-time backtest metrics across all 5 test periods)
   - `Granite_CVE_Analyzer/granite_cache.json` (Persistent Granite 4 3B extraction cache)

2. **Regenerate the Interactive HTML Dashboard (`dashboard.html`)**:
   ```powershell
   python generate_dashboard.py
   ```
   Features:
   - **Out-of-Time Backtest & Safe/Unsafe Columns Audit** panel (values read directly from `backtest_results.json`; toggle with the header button)
   - Top-order filter to toggle between **All Entries**, **With EPSS Values**, and **Without EPSS Values (`EPSS = 0`)**
   - Sort by predicted KEV risk, EPSS, vendor prior-KEV count, CNA CVSS, rank, CVE ID, or effective date, with an **Ascending / Descending** toggle
   - Page size selector for **10, 25, 50, 100, 250, or 500** results per page with a sticky **SECTION AVERAGES** row heading each page in the table
   - Snapshot date normalization (`effective_date = snapshot_month` whenever `published > snapshot_month`)

3. **Compare Any Two CSV Files (`csv_compare_agent`)**:
   Compares structural schemas, data types, null distributions, and key-based record diffs across large datasets, and exports a Markdown audit:
   ```powershell
   python demo_compare.py
   # or via CLI
   python -m csv_compare_agent.cli data/exploit_signals_2024.csv data/exploit_signals_2025.csv --report signals_audit.md
   ```

4. **Deep Inspection of a Specific CVE**:
   ```powershell
   python Granite_CVE_Analyzer/CVE_Analyzer.py CVE-2026-8037 --prompt
   ```

---

## 🗂️ Project Structure

```
Hackermen_Sheridan_Datathon_26Q3/
├── .gitattributes                     # Git LFS tracking configuration for large CSV files
├── .gitignore                        # Python cache and temporary file ignores
├── README.md                         # Project documentation and methodology
├── DATATHON_ANALYSIS_FINDINGS.md     # Leakage audit, backtest results, and top candidates
├── top500.csv                        # Top 500 predicted KEV candidates (leak-free)
├── all_cves_assessed.csv             # All 72,670 scoreboard CVEs scored and ranked
├── dashboard.html                    # Interactive threat & backtest dashboard
├── generate_dashboard.py             # Script to regenerate dashboard.html
├── demo_compare.py                   # Demo comparing 2024 vs 2025 exploit signals
│
├── csv_compare_agent/                # Multi-CSV comparison agent package
│   ├── __init__.py                   # Package exports
│   ├── agent.py                      # CSVCompareAgent core class
│   ├── profiler.py                   # Schema diffing, key diffing, and statistical engine
│   ├── epss_weighting.py             # EPSS v4 version-aware weighting logic
│   └── cli.py                        # Command-line interface for comparing datasets
│
├── Granite_CVE_Analyzer/             # IBM Granite AI analysis suite
│   ├── leak_free_model.py            # 4-fix leak-free pipeline: features, backtest, scoring, Granite
│   ├── backtest_results.json         # Out-of-time backtest metrics (source of truth for dashboard)
│   ├── granite_cache.json            # Persistent Granite 4 3B extraction cache
│   ├── CVE_Analyzer.py               # Deep CVE lookup, KEV correlation, and Granite prompt builder
│   └── granite_agent.py              # Earlier scoring agent connecting to Ollama
│
└── data/                             # Datathon CSV datasets (tracked via Git LFS)
    ├── vulnerabilities.csv           # 401k CVE records with CVSS, NVD status, CWE, descriptions
    ├── affected_products.csv         # 3.15M CVE-to-vendor/product records (NOT used in scoring: leaky)
    ├── exploit_signals_2024.csv      # Monthly EPSS v3 and exploit telemetry (2024)
    ├── exploit_signals_2025.csv      # Monthly EPSS v3/v4 telemetry (2025)
    ├── scoreboard_2026.csv           # 72k target evaluation benchmark (2026)
    ├── known_exploited.csv           # CISA Known Exploited Vulnerabilities catalog
    ├── weakness_types.csv            # MITRE CWE weakness taxonomy
    └── references.csv                # External advisory URLs (NOT used in scoring: leaky)
```

---

## 🛡️ License & Team
Developed for **Sheridan Datathon 26Q3** by **Team Hackermen**.
All datasets are governed by their respective sources (CISA, NVD/NIST, FIRST EPSS, MITRE CWE).
