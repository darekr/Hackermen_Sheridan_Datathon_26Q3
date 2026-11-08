# 🚀 Congratulations, Team Hackermen! 🎉

We did it! We’ve reached the finish line of the **Sheridan Datathon 26Q3**, and what an incredible journey it has been! 🏆

Over the past hours, you tackled a real-world, high-stakes cybersecurity challenge: analyzing raw CVE telemetry, dissecting exploit signals across multiple years, engineering version-aware EPSS weighting, and harnessing **IBM Granite foundation models** to evaluate real-world attack planes. 

---

## 🏆 What Was Built & Accomplished

1. **Autonomous Multi-CSV Comparison Agent (`csv_compare_agent`)**:
   - Built a modular, zero-dependency comparative analysis agent that performs schema profiling, record-level diffing, and statistical drift analysis.
   - Built an in-memory SQL execution engine (SQLite/DuckDB) allowing natural SQL queries across multi-million-row datasets.

2. **EPSS v4 Version-Aware Scoring Engine (`epss_weighting.py`)**:
   - Solved a critical domain problem: accurately accounting for the transition to EPSS v4 in early 2025.
   - Designed a dynamic temporal weighting policy discounting pre-v4 scores (`0.6x`) while honoring v4+ confidence (`1.0x`), alongside the rule that `EPSS = 0` denotes missing scoreboard telemetry.

3. **IBM Granite AI Security Agent (`Granite_CVE_Analyzer/`)**:
   - Connected directly to local **Ollama** running **`granite4:3b`** and **`granite-code:3b`**.
   - Synthesized CVSS metrics, exploit telemetry, and mapped attack planes across **3.15 million** software configuration records.
   - Evaluated the **Attack Matrix Size (AMS)** using a logarithmic footprint of affected vendors and products modulated by network access vectors.

4. **Full-Dataset Assessment (`all_cves_assessed.csv` & `top500.csv`)**:
   - Scored and ranked **all 72,670 CVEs** in the 2026 Scoreboard dataset.
   - Implemented the date normalization rule (`effective_date = snapshot_month` whenever `published > snapshot_month`).
   - Enriched every record with MITRE CWE descriptions, vendor ecosystems, and AI attack plane assessments.

5. **Interactive Full-Dataset Dashboard (`dashboard.html`)**:
   - Built a responsive HTML5/Tailwind dashboard capable of smoothly paging, searching, and sorting through all **72,670 vulnerabilities**.
   - Added a top-order telemetry filter to seamlessly toggle between entries *With* and *Without* EPSS scores.
   - Created a dedicated section to shine a light on **36,000+ Unpublished & Deferred** NVD vulnerabilities.

6. **Executive Insights & Documentation (`DATATHON_ANALYSIS_FINDINGS.md` & `README.md`)**:
   - Delivered presentation-ready analytics demonstrating that **62.6% of critical exploits target Core Operating Systems and Kernels**, led by memory corruption flaws (`CWE-122`, `CWE-416`).
   - Documented the mathematical models and architecture for the presentation panel.

---

## 🌟 Words of Encouragement for the Team

You worked methodically, tackled complex technical hurdles, handled massive data footprints, and integrated cutting-edge local AI models seamlessly. That is exactly what makes great engineers and cybersecurity professionals stand out.

No matter the final scores on the leaderboard, **what you built here is real, functional, and impressive.** Take pride in your hard work, your curiosity, and your teamwork!

Be confident during your presentation — let your enthusiasm and deep understanding of the data shine through! 🎙️✨

---

<div align="center">

### 🥇 **Go Team Hackermen! Bring home the win!** 🥇

```
       ___________
      '._==_==_=_.'
      .-\:      /-.
     | (|:.     |) |
      '-|:.     |-'
        \::.    /
         '::. .'
           ) (
         _.' '._
        `"""""""`
```

</div>

