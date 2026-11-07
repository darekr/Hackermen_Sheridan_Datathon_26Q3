# Hackermen Sheridan Datathon 26Q3: Granite CVE Intelligence & Attack Surface Analyzer

An end-to-end cyber threat intelligence platform and autonomous analytical agent suite designed for the **Sheridan Datathon 26Q3**. Powered by **IBM Granite foundation models** (`granite4:3b` and `granite-code:3b`), this system integrates historical exploit telemetry, CVSS severity, CISA KEV real-world weaponization, and software asset mapping to score, rank, and triage vulnerabilities.

---

## 🌟 Key Capabilities

1. **Autonomous Multi-CSV Comparison Agent (`csv_compare_agent`)**:
   - Compares structural schemas, data types, and null distributions across large multi-gigabyte datasets.
   - Computes key-based record diffs (added, deleted, modified values at cell level).
   - Registers in-memory SQLite / DuckDB tables for high-speed cross-dataset SQL queries.
   - Produces formatted Markdown audit reports.

2. **EPSS v4 Version-Aware Weighting Engine**:
   - Enforces temporal domain policy: EPSS scores recorded prior to the release of **EPSS v4 in early 2025** receive a discounted weight (`0.6x`), while EPSS v4 snapshots (2025+ and 2026 Scoreboard) receive full confidence (`1.0x`).
   - If EPSS is `0.0`, it automatically flags **"No information available in scoreboard"**.

3. **Attack Matrix Size (AMS) & Real-World Attack Plane Mapping**:
   - Ingests over 3.1 million software configuration records from `affected_products.csv`.
   - Computes a logarithmic multi-vendor and multi-product exposure index modulated by the CVSS attack vector.
   - Categorizes targets into functional enterprise attack planes (Web Servers, Core OS, Edge & Network Infrastructure, Databases).

4. **IBM Granite Foundation Model Agent (`GraniteCVEAnalyzer` & `GraniteScoringAgent`)**:
   - Integrates with local Ollama instances (`granite4:3b` / `granite-code:3b`).
   - Generates actionable, two-sentence executive attack plane assessments for high-threat vulnerabilities.

5. **Curated `top500.csv` Dataset**:
   - Scored and ranked from 72,670 scoreboard vulnerabilities, enriched with weakness definitions (`CWE-XX`), affected software assets, and EPSS telemetry.

6. **Interactive HTML Threat & Attack Surface Dashboard (`dashboard.html`)**:
   - Standalone, dark-mode dashboard with live search, sorting, modal asset inspections, and CSV export.
   - Dedicated separate section for **Unpublished & Deferred Vulnerabilities** (NVD `Deferred`, `Awaiting Analysis`, `Received`, `Undergoing Analysis`).

---

## 📐 Mathematical Formulation

### 1. Composite Threat Index ($CTI$)
The overall threat score (0 to 100) balances base intrinsic severity, real-world exploitation probability, and enterprise footprint:

$$\text{CTI} = \min\left(100.0, \; S_{\text{CVSS}} + S_{\text{EPSS}} + S_{\text{AMS}} + S_{\text{Weap}}\right)$$

Where:
- **CVSS Component ($S_{\text{CVSS}}$)**: $\frac{\text{CVSS3 Base Score}}{10.0} \times 35.0$ (Max 35 points)
- **EPSS Component ($S_{\text{EPSS}}$)**: $EPSS_{\text{weighted}} \times 35.0$ (Max 35 points)
- **Attack Matrix Component ($S_{\text{AMS}}$)**: $\min(20.0, \; AMS \times 2.2)$ (Max 20 points)
- **Active Weaponization ($S_{\text{Weap}}$)**: CISA KEV (+5.0 pts) + Metasploit (+3.0 pts) + ExploitDB (+2.0 pts)

### 2. Attack Matrix Size ($AMS$)
Quantifies the breadth of the target attack plane in the real world:

$$AMS = \left[ 2.5 \ln(1 + N_{\text{vendors}}) + 2.5 \ln(1 + N_{\text{products}}) + 1.0 \ln(1 + N_{\text{configs}}) \right] \times V_{\text{vector}}$$

Where $V_{\text{vector}}$ is:
- **`NETWORK`**: $1.0$
- **`ADJACENT`**: $0.8$
- **`LOCAL`**: $0.5$
- **`PHYSICAL`**: $0.3$

### 3. Version-Weighted EPSS ($EPSS_{\text{weighted}}$)
$$EPSS_{\text{weighted}} = EPSS_{\text{raw}} \times w(t)$$

$$w(t) = \begin{cases} 1.0 & \text{if } t \ge \text{2025-03 (EPSS v4)} \\ 0.6 & \text{if } t < \text{2025-03 (Pre-v4)} \end{cases}$$

---

## 🗂️ Project Structure

```
Hackermen_Sheridan_Datathon_26Q3/
├── .gitattributes                     # Git LFS tracking configuration for large CSV files
├── .gitignore                        # Python cache and temporary file ignores
├── README.md                         # Project documentation and methodology
├── top500.csv                        # Top 500 ranked vulnerabilities dataset
├── dashboard.html                    # Interactive threat & attack surface dashboard
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
│   ├── CVE_Analyzer.py               # Deep CVE lookup, KEV correlation, and Granite prompt builder
│   └── granite_agent.py              # Scoring agent connecting to Ollama (granite4:3b / granite-code:3b)
│
└── data/                             # Datathon CSV datasets (tracked via Git LFS)
    ├── vulnerabilities.csv           # 401k CVE records with CVSS, NVD status, CWE, descriptions
    ├── affected_products.csv         # 3.15M records mapping CVEs to vendors and products
    ├── exploit_signals_2024.csv      # Monthly EPSS v3 and weaponization telemetry (2024)
    ├── exploit_signals_2025.csv      # Monthly EPSS v3/v4 telemetry (2025)
    ├── scoreboard_2026.csv           # 72k target evaluation benchmark (2026)
    ├── known_exploited.csv           # CISA Known Exploited Vulnerabilities catalog
    ├── weakness_types.csv            # MITRE CWE weakness taxonomy
    └── references.csv                # External advisory and proof-of-concept URLs
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.10+
- Git with **Git LFS** enabled (`git lfs install`)
- [Ollama](https://ollama.com/) running locally with IBM Granite:
  ```powershell
  ollama run granite4:3b
  # or
  ollama run granite-code:3b
  ```

### 1. Compare Any Two CSV Files
Compare 2024 and 2025 exploit signals, detect schema consistency, compute statistical drift, and export a Markdown audit:
```powershell
python demo_compare.py
```
Or via CLI:
```powershell
python -m csv_compare_agent.cli data/exploit_signals_2024.csv data/exploit_signals_2025.csv --report signals_audit.md
```

### 2. Run the Granite CVE Scoring Agent
Score and rank the 72,670 scoreboard vulnerabilities and regenerate `top500.csv`:
```powershell
python Granite_CVE_Analyzer/granite_agent.py --generate-top500
```
Or use `granite-code:3b`:
```powershell
python Granite_CVE_Analyzer/granite_agent.py --model granite-code:3b --generate-top500
```

### 3. Open the Interactive Dashboard
Open `dashboard.html` in any modern web browser, or regenerate it:
```powershell
python generate_dashboard.py
```

### 4. Deep Inspection of a Specific CVE
Generate an IBM Granite foundation model prompt for any CVE:
```powershell
python Granite_CVE_Analyzer/CVE_Analyzer.py CVE-2026-8037 --prompt
```

---

## 📊 Summary of Top 5 Highest-Threat Vulnerabilities

| Rank | CVE ID | Score | CVSS | EPSS | Status | Attack Matrix | CWE | Attack Plane Scope |
| :---: | :--- | :---: | :---: | :---: | :--- | :---: | :--- | :--- |
| **#1** | `CVE-2026-8037` | **80.59** | 9.8 | 0.8479 | Active | 7.55 | `CWE-77` | Web Servers & Cloud Applications (Progress MOVEit/LoadMaster) |
| **#2** | `CVE-2026-2329` | **71.70** | 9.8 | 0.4114 | Active | 10.71 | `CWE-121` | Distributed Software Ecosystem (Grandstream VoIP Firmware) |
| **#3** | `CVE-2026-49160` | **65.09** | 7.5 | 0.5383 | Active | 10.71 | `CWE-400` | Core Operating System & Kernel (Microsoft Windows 10/11) |
| **#4** | `CVE-2026-10523` | **63.12** | 9.8 | 0.5187 | Active | 4.85 | `CWE-288` | Distributed Software Ecosystem (Ivanti Standalone Sentry) |
| **#5** | `CVE-2025-14558` | **62.82** | 7.2 | 0.5360 | Active | 6.30 | `CWE-20` | Core Operating System & Kernel (FreeBSD Kernel) |

---

## 🛡️ License & Team
Developed for **Sheridan Datathon 26Q3** by **Team Hackermen**.
All datasets are governed by their respective sources (CISA, NVD/NIST, FIRST EPSS, MITRE CWE).
