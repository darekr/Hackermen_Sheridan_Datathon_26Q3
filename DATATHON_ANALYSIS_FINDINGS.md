# Sheridan Datathon 26Q3: Leak-Free Predictive Analysis & Temporal Backtest Findings

**Project:** Hackermen Sheridan Datathon 26Q3  
**Foundation Model:** IBM Granite 4:3B (`granite4:3b`) + Leak-Free Gradient Boosting (`HistGradientBoostingClassifier`) & Auditable Weighted Formula  
**Target Dataset:** Scoreboard 2026 (72,670 evaluated CVEs) + Historical Out-of-Time Backtest Pool (2024–2025, 87,020 CVEs)

---

## Executive Summary

To ensure our vulnerability rankings generalize to real-world security operations without any post-hoc data leakage, we architected a **4-Fix Leak-Free Predictive Pipeline** (`Granite_CVE_Analyzer/leak_free_model.py`):

1. **Fix 1 — Strict Data Leakage Prevention (Safe vs. Unsafe Columns Audit)**: Dropped all columns populated by NIST/NVD *after* exploitation becomes public (`affected_products.csv` CPE counts, `nvd_status`, `n_affected_cpes`, `n_references`, NIST's own `cvss3_score` where `cvss3_source == 'nvd@nist.gov'`, `references.csv` links, and NIST-assigned CWEs). Replaced the leaky CPE footprint score by extracting vendor, product, internet-facing edge/appliance flags, and attack types directly from `description` and `assigner`, matched against how often that vendor/assigner appeared in `known_exploited.csv` **strictly on or before** the snapshot month (`date_added <= end_of_snapshot_month`).
2. **Fix 2 — Out-of-Time Temporal Backtesting (2024–2025)**: Rebuilt the exact scoreboard setup across 2024–2025 (`in_kev == 0` at snapshot month, predicting future KEV additions up to `2025-12-31`), always training on older months and testing on newer unseen months. Across 5 out-of-time test periods (91 future KEV additions), our **Leak-Free GBDT + Readable Model** and our **Strict No-CVSS Model** each caught **48 / 91 (52.7%)** in the per-period Top 500, compared with **Exploit-then-EPSS** (`35 / 91`), **EPSS-First** (`24 / 91`), and **CVSS-First** (`7 / 91`). Our models match or beat every baseline in every period (2025-Q2 is a raw tie with Exploit-then-EPSS at 12).
3. **Fix 3 — Anti-Hallucination & Grounded Why-Explanations**: Enforced a deterministic post-check verifier (`verify_and_sanitize_explanation`) that blocks any output claiming `"actively exploited"` or `"exploited in the wild"` (since outputs are predictions of future risk) and rejects hallucinated numbers. Every explanation explicitly names the verified drivers that ranked the CVE highly.
4. **Fix 4 — Semantic Description Similarity & Cached Granite 4 3B Extraction**: Computed 48-dimensional TF-IDF + SVD semantic embeddings across all descriptions to measure cosine similarity against **strictly prior** KEV descriptions, and used local `granite4:3b` (cached in `Granite_CVE_Analyzer/granite_cache.json`) for structured feature extraction (`vendor`, `product`, `internet_facing`, `attack_type`) and grounded explanations.

---

## 1. Fix 1 Deliverable: Columns Used and Why (Safe vs. Unsafe Audit)

| Column / Table | Status | Why It Is Safe or Unsafe at Snapshot Time |
| :--- | :---: | :--- |
| `epss` (at `snapshot_month`) | **SAFE (Used)** | Recorded directly in the monthly snapshot (`exploit_signals_2024/2025.csv` & `scoreboard_2026.csv`) prior to future exploitation. |
| `is_epss_v4` (`snapshot_month >= 2025-03`) | **SAFE (Used)** | Captures the March 2025 EPSS v3 $\rightarrow$ v4 regime shift directly as a model feature instead of a guessed multiplier. |
| `nuclei`, `metasploit`, `exploitdb`, `poc_github` | **SAFE (Used)** | Public exploit & PoC flags observed at the end of the snapshot month (`r = 0.1288` correlation for `nuclei`). |
| `description` (`vulnerabilities.csv`) | **SAFE (Used)** | Written by the CNA/vendor when the CVE is published. Used to extract vendor, product, edge/appliance flags, unauthenticated RCE/auth-bypass, and SVD similarity to prior KEV descriptions. |
| `assigner` (`vulnerabilities.csv`) | **SAFE (Used)** | Identifies the originating CNA at publication time. Matched against strictly prior KEV history. |
| `known_exploited.csv` (`date_added <= snapshot_month`) | **SAFE (Used)** | Strictly filtered to KEV entries added **on or before** the snapshot month to compute `vendor_prior_kev_count`, `vendor_prior_ransom_count`, and `assigner_prior_kev_count` with zero future leakage. |
| `cvss3_score` (`cvss3_source != 'nvd@nist.gov'`) | **SAFE (Optional)** | Provided by the vendor/CNA or CISA at publication time. Also evaluated in a **Strict No-CVSS** variant that drops CVSS completely. |
| `published` vs `snapshot_month` | **SAFE (Normalized)** | Whenever `published > snapshot_month`, we assume `effective_date = snapshot_month` to prevent post-snapshot date anomalies. |
| `affected_products.csv` & `n_affected_cpes` | **UNSAFE (Dropped)** | **Severe Leakage:** NIST populates CPE product mappings *after* a CVE becomes high-profile or enters KEV. Replaced with description/CNA vendor extraction + prior KEV counts. |
| `nvd_status` (`vulnerabilities.csv`) | **UNSAFE (Dropped)** | **Severe Leakage:** `Analyzed` vs. `Awaiting Analysis` / `Deferred` reflects whether NIST prioritized the CVE later. |
| `cvss3_score` (`cvss3_source == 'nvd@nist.gov'`) | **UNSAFE (Dropped)** | **Severe Leakage:** 196,952 rows scored post-hoc by NIST analysts (`nvd@nist.gov`),plus blank-score patterns that reveal NVD backlog state. |
| `references.csv` & `n_references` | **UNSAFE (Dropped)** | **Severe Leakage:** Accumulates post-disclosure advisories and CISA KEV links over time. |
| `cwe_ids` (when NIST-assigned) | **UNSAFE (Dropped)** | Filled in during post-hoc NVD enrichment; replaced by CNA-only CWE or description-extracted attack class. |

---

## 2. Fix 2 Deliverable: Out-of-Time Temporal Backtest (2024–2025)

### Data Quirks & Integrity Fixes Handled in Backtesting
- **62 Pre-Publication KEV Anomalies**: Exactly 62 CVEs in `known_exploited.csv` have `date_added < published` (14 in the 2024–2025 pool). These are excluded from the candidate pool since they were already in KEV prior to publication.
- **February 2025 Missing ~14,500 CVEs**: `exploit_signals_2025.csv` has a telemetry drop in `2025-02` where ~14,500 CVEs vanish and reappear in `2025-03`. Matching each 2024–2025 CVE to its earliest available snapshot month $\ge$ `pub_month` recovers 4,930 CVEs cleanly, yielding **87,020 non-KEV historical candidates** with **118 total future KEV additions** (91 in the out-of-time test windows from July 2024 – December 2025).
- **EPSS v4 Regime Change (March 2025)**: Handled via `is_epss_v4`, `epss_x_v4`, and `epss_pre_v4` interaction features learned directly on historical data.

### Out-of-Time Backtest Comparison: Our Models vs. 3 Baselines

Each test period is trained **strictly on older months** and evaluated on newer unseen months. We report both **Raw Top-500 Catches** and **Scaled Top-500 Equivalent Catches** (where $K_{\text{scaled}} = \text{round}(500 \times N_{\text{period}} / 72,670)$ matches the selectivity of picking 500 out of the 72,670 scoreboard):

| Out-of-Time Test Period | Train Window | Test Pool ($N$) | Future KEVs | Baseline 1: `CVSS-First` | Baseline 2: `EPSS-First` | Baseline 3: `Exploit-then-EPSS` | `Readable Score` (Ours) | `Our Model` (GBDT + Readable) | `Strict No-CVSS` (Ours) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **2024-Q3 (Jul–Sep 2024)** | `2024-01..06` | 8,440 | 18 | 0 *(0)* | 3 *(2)* | 6 *(3)* | 8 *(5)* | **9 *(4)*** | **9 *(4)*** |
| **2024-Q4 (Oct–Dec 2024)** | `2024-01..09` | 11,000 | 21 | 0 *(0)* | 2 *(2)* | 5 *(3)* | 5 *(3)* | **7 *(5)*** | **7 *(5)*** |
| **2025-Q1 (Jan–Mar 2025, v4 Shift)** | `2024-01..12` | 12,139 | 18 | 3 *(1)* | 7 *(3)* | 6 *(3)* | 7 *(4)* | **13 *(5)*** | **13 *(5)*** |
| **2025-Q2 (Apr–Jun 2025, Post-v4)** | `2024-01..25-03` | 11,942 | 17 | 2 *(2)* | 9 *(6)* | 12 *(9)* | 12 *(10)* | **12 *(10)*** | **12 *(11)*** |
| **2025-H2 (Jul–Dec 2025, Latest)** | `2024-01..25-06` | 23,688 | 17 | 2 *(1)* | 3 *(2)* | 6 *(5)* | 7 *(5)* | **7 *(6)*** | **7 *(6)*** |
| **SUM OF PER-PERIOD TOP-500 *(Scaled)*** | — | **67,209** | **91** | **7 *(4)*** | **24 *(15)*** | **35 *(23)*** | **39 *(27)*** | **48 *(30)*** | **48 *(31)*** |
| **POOLED OUT-OF-TIME TOP-500** | — | **67,209** | **91** | **4** | **14** | **24** | **29** | **28** | **28** |

*(Note: Numbers outside parentheses are Raw Top-500 catches per period; numbers in parentheses are Scaled Top-500 catches $K_{\text{scaled}}$. Source of truth: `Granite_CVE_Analyzer/backtest_results.json`.)*

### Visual Comparison of Out-of-Time Future KEV Catches (Out of 91 Future KEVs)

```
Strict No-CVSS (Ours)       ████████████████████████████████████████████████   48 / 91 (52.7% | 31 Scaled)
Our Model (GBDT + Readable) ████████████████████████████████████████████████   48 / 91 (52.7% | 30 Scaled)
Readable Formula (Ours)     ███████████████████████████████████████            39 / 91 (42.9% | 27 Scaled)
Baseline: Exploit-then-EPSS ███████████████████████████████████                35 / 91 (38.5% | 23 Scaled)
Baseline: EPSS-First        ████████████████████████                           24 / 91 (26.4% | 15 Scaled)
Baseline: CVSS-First        ███████                                             7 / 91 ( 7.7% |  4 Scaled)
```

> [!IMPORTANT]
> **Key Backtest Results:**
> 1. **Matches or beats every baseline in every period**: Summed across periods, our leak-free model catches **48 vs 35** future KEVs for `Exploit-then-EPSS` (+37%), **2.0x** `EPSS-First` (48 vs 24), and **6.9x** `CVSS-First` (48 vs 7). In 2025-Q2 it ties `Exploit-then-EPSS` on raw catches (12 vs 12) and wins on scaled catches (10–11 vs 9).
> 2. **CVSS is not needed**: The `Strict No-CVSS` variant drops CVSS entirely and catches the same **48 / 91** raw (31 scaled).

> [!WARNING]
> **Caveat on optimism:** The gradient-boosting component is always trained strictly on older months. However, the weights in the readable formula (`compute_readable_score`) were adjusted once after seeing an earlier run of this same backtest, so the readable and combined scores are somewhat optimistic. A fully clean estimate would need a period that was never looked at during tuning (e.g., 2026 KEV additions once they're known).

---

## 3. Empirical Feature Correlations with Future KEV Addition (2024–2025)

Measured across all 87,020 historical non-KEV candidates:

| Rank | Leak-Free Feature | Correlation ($r$) with Future KEV | Source |
| :---: | :--- | :---: | :--- |
| 1 | `nuclei` (Nuclei scanner template at snapshot) | `+0.1288` | Snapshot Signals |
| 2 | `exploit_flag_count` (Sum of public exploit flags) | `+0.1249` | Snapshot Signals |
| 3 | `epss_pre_v4` / `epss` (Snapshot EPSS probability) | `+0.1041` / `+0.0997` | Snapshot Signals |
| 4 | `epss_x_exploit` (Interaction: EPSS $\times$ Exploit count) | `+0.1005` | Engineered Interaction |
| 5 | `has_any_exploit` (Any public exploit at snapshot) | `+0.0936` | Snapshot Signals |
| 6 | `poc_github` (GitHub PoC at snapshot) | `+0.0843` | Snapshot Signals |
| 7 | `metasploit` (Metasploit module at snapshot) | `+0.0502` | Snapshot Signals |
| 8 | `is_unauthenticated` (Unauthenticated indicator in description) | `+0.0373` | Description Extraction |
| 9 | `exploitdb` (ExploitDB entry at snapshot) | `+0.0368` | Snapshot Signals |
| 10 | `prior_kev_sim_top5` (SVD similarity to strictly prior KEVs) | `+0.0292` | Semantic Embeddings |
| 11 | `edge_x_unauth_or_rce` (Edge appliance $\times$ Unauth/RCE) | `+0.0291` | Description Extraction |
| 12 | `atk_auth_bypass` (Authentication bypass in description) | `+0.0254` | Description Extraction |

---

## 4. Top 10 Predicted KEV Candidates in Scoreboard 2026 (`top500.csv`)

Every explanation is verified by `verify_and_sanitize_explanation()` to guarantee zero `"actively exploited"` hallucinations and cite exact model drivers:

| Rank | CVE ID | Predicted Score | Snapshot EPSS | CNA CVSS | Vendor (Extracted) | Prior KEVs ($\le$ Snap) | Exploit Flags | Grounded Why-Explanation (Verified) |
| :---: | :--- | :---: | :---: | :---: | :--- | :---: | :---: | :--- |
| **#1** | `CVE-2026-8037` | **80.41** | 0.84793 | *Excluded (NVD)* | `progress` | 8 (4 ransom) | 2 (Nuclei, PoC) | Vendor `progress` has 8 prior KEVs; internet-facing ADC appliance; RCE + command injection; Nuclei + GitHub PoC; EPSS v4 = 0.84793; 0.93 sim to KEV `CVE-2019-7256`. |
| **#2** | `CVE-2026-10523` | **67.19** | 0.51870 | *Excluded (NVD)* | `ivanti` | 30 (12 ransom) | 1 (PoC) | Vendor `ivanti` has 30 prior KEVs; unauthenticated authentication bypass (Ivanti Sentry); GitHub PoC; EPSS v4 = 0.51870; 0.96 sim to KEV `CVE-2024-7593`. |
| **#3** | `CVE-2026-43500` | **64.28** | 0.40266 | *Excluded (NVD)* | `linux` | 23 (2 ransom) | 3 (MSF, EDB, PoC) | Vendor `linux` has 23 prior KEVs; Metasploit + ExploitDB + GitHub PoC; EPSS v4 = 0.40266; 0.87 sim to KEV `CVE-2025-38352`. |
| **#4** | `CVE-2026-6875` | **63.54** | 0.24489 | *Excluded (NVD)* | `servicenow` | 2 | 2 (Nuclei, PoC) | Vendor `servicenow` has 2 prior KEVs; unauthenticated RCE; Nuclei + GitHub PoC; EPSS v4 = 0.24489; 0.89 sim to KEV `CVE-2025-23209`. |
| **#5** | `CVE-2026-2699` | **61.84** | 0.23777 | 9.8 (CNA) | `progress` | 8 (4 ransom) | 2 (Nuclei, PoC) | Vendor `progress` has 8 prior KEVs; unauthenticated RCE; Nuclei + GitHub PoC; EPSS v4 = 0.23777; CNA CVSS = 9.8; 0.92 sim to KEV `CVE-2024-4885`. |
| **#6** | `CVE-2026-48909` | **60.84** | 0.07638 | *Excluded (NVD)* | `joomla` | 1 | 3 (Nuclei, EDB, PoC) | Unauthenticated cookie deserialization RCE; Nuclei + ExploitDB + GitHub PoC; EPSS v4 = 0.07638; 0.93 sim to KEV `CVE-2025-3248`. |
| **#7** | `CVE-2026-19478` | **60.70** | 0.06001 | *Excluded (NVD)* | `gitlab` | 2 (1 ransom) | 2 (Nuclei, PoC) | Vendor `gitlab` has 2 prior KEVs; internet-facing GitLab instance; unauthenticated access; Nuclei + GitHub PoC; EPSS v4 = 0.06001; 0.87 sim to KEV `CVE-2024-9537`. |
| **#8** | `CVE-2025-71257` | **59.43** | 0.03440 | *Excluded (NVD)* | *(not extracted — BMC)* | 0 | 2 (Nuclei, PoC) | Internet-facing BMC FootPrints ITSM; unauthenticated REST API auth bypass; Nuclei + GitHub PoC; EPSS v4 = 0.03440; 0.82 sim to KEV `CVE-2024-4358`. |
| **#9** | `CVE-2026-39808` | **59.39** | 0.13099 | 9.8 (CNA) | `fortinet` | 23 (14 ransom) | 2 (Nuclei, PoC) | Vendor `fortinet` has 23 prior KEVs; command injection (FortiSandbox); Nuclei + GitHub PoC; EPSS v4 = 0.13099; CNA CVSS = 9.8; 0.94 sim to KEV `CVE-2025-58034`. |
| **#10** | `CVE-2026-71362` | **58.93** | 0.25136 | 9.1 (CNA) | `adobe` | 76 (11 ransom) | 2 (Nuclei, PoC) | Vendor `adobe` has 76 prior KEVs; Nuclei + GitHub PoC; EPSS v4 = 0.25136; CNA CVSS = 9.1; 0.71 sim to KEV `CVE-2023-29298`. |

> [!NOTE]
> Vendor extraction misses some vendors that are only named in product text (e.g., #8 BMC is labelled `unknown`, so it gets no prior-KEV credit). That under-ranks rather than over-ranks those CVEs.
