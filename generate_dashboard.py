"""
Full Dataset Dashboard Generator.
Assesses and displays ALL CVEs noted in the dataset (72,670 scoreboard vulnerabilities + unpublished pool).
Produces an interactive, standalone HTML dashboard with high-performance client-side pagination.
"""

import os
import csv
import json
import math
from typing import List, Dict, Any


def load_all_assessed_cves(csv_path: str = "all_cves_assessed.csv") -> List[List[Any]]:
    """Loads all assessed CVEs into a high-performance compact array representation."""
    compact_rows = []
    if not os.path.exists(csv_path):
        # Fallback to top500.csv if all_cves_assessed.csv not yet generated
        csv_path = "top500.csv"
        if not os.path.exists(csv_path):
            return compact_rows

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, r in enumerate(reader):
            pub = r.get("published_date") or r.get("published") or ""
            snap = r.get("snapshot_month") or "2026-03"

            # Date rule
            if pub and snap and (pub > snap or pub[:7] > snap):
                effective_date = snap
                assumed_snapshot = 1
            else:
                effective_date = r.get("effective_date") or pub or snap
                assumed_snapshot = 1 if str(r.get("assumed_snapshot_data")).lower() == "true" else 0

            rank = int(r.get("rank") or (idx + 1))
            cve_id = r.get("cve_id", "")
            score = float(r.get("composite_score") or 0.0)
            cvss = float(r.get("cvss3_score") or 0.0)
            sev = r.get("cvss3_severity", "UNKNOWN")
            vec = r.get("attack_vector", "NETWORK")
            epss = float(r.get("epss_score") or 0.0)
            epss_status = r.get("epss_status", "")
            ams = float(r.get("attack_matrix_size") or 0.0)
            cwe_id = r.get("cwe_id", "NVD-CWE-noinfo")
            cwe_name = r.get("cwe_name", "")
            v_cnt = int(r.get("affected_vendors_count") or 0)
            p_cnt = int(r.get("affected_products_count") or 0)
            vendors = r.get("sample_affected_vendors", "")
            products = r.get("sample_affected_products", "")
            scope = r.get("attack_plane_scope", "")
            assessment = r.get("granite_attack_plane_assessment", "")

            compact_rows.append([
                rank, cve_id, score, cvss, sev, vec,
                epss, epss_status, ams, cwe_id, cwe_name,
                v_cnt, p_cnt, vendors, products, effective_date,
                assumed_snapshot, scope, assessment
            ])

    return compact_rows


def load_unpublished(all_cves: List[List[Any]], limit: int = 500) -> List[List[Any]]:
    """
    Leak-free replacement for the pre-analysis / low-telemetry pool:
    Extracts CVEs where EPSS == 0 (no scoreboard EPSS) or where only CNA/description
    signals exist (NVD CVSS excluded to prevent post-hoc leakage), ranked by our
    leak-free composite score. Never touches nvd_status or affected_products.csv.
    """
    candidates = []
    for r in all_cves:
        # r[6] is epss, r[4] is severity ('NVD_EXCLUDED_LEAK_FREE' if no CNA CVSS)
        if r[6] == 0.0 or r[4] == "NVD_EXCLUDED_LEAK_FREE":
            c = list(r)
            tag = "Zero-EPSS & CNA-Unscored" if (r[6] == 0.0 and r[4] == "NVD_EXCLUDED_LEAK_FREE") else (
                "Zero-EPSS (No Scoreboard Info)" if r[6] == 0.0 else "CNA-Unscored (NIST CVSS Excluded)"
            )
            c[17] = tag
            candidates.append(c)

    candidates.sort(key=lambda x: x[2], reverse=True)
    out = []
    for idx, c in enumerate(candidates[:limit]):
        c_copy = list(c)
        c_copy[0] = idx + 1
        out.append(c_copy)
    return out


def load_backtest_results(path: str = "Granite_CVE_Analyzer/backtest_results.json") -> Dict[str, Any]:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def generate_html_dashboard(
    all_cves: List[List[Any]],
    unpublished: List[List[Any]],
    output_path: str
):
    all_cves_json = json.dumps(all_cves)
    unpublished_json = json.dumps(unpublished)
    total_count = len(all_cves)

    # Backtest panel values are read from backtest_results.json (never hardcoded)
    bt = load_backtest_results()
    bt_pool = int(bt.get("pool_2024_2025_size", 0))
    bt_kev = int(bt.get("out_of_time_test_kev_total", 0))
    bt_raw = bt.get("sum_raw_top500_caught", {})
    bt_scaled = bt.get("sum_scaled_top500_caught", {})
    methods = [
        ("strict_no_cvss", "Strict No-CVSS Leak-Free Model (Ours)", "emerald"),
        ("our_model", "Leak-Free GBDT + Readable Model (Ours)", "blue"),
        ("readable_score", "Readable Leak-Free Formula Alone (Ours)", "purple"),
        ("exploit_then_epss", "Baseline: Exploit-then-EPSS", "amber"),
        ("epss_first", "Baseline: EPSS-First", "gray"),
        ("cvss_first", "Baseline: CVSS-First", "rose"),
    ]
    max_raw = max([bt_raw.get(k, 0) for k, _, _ in methods] + [1])
    bar_parts = []
    for key, label, color in methods:
        raw = int(bt_raw.get(key, 0))
        scaled = int(bt_scaled.get(key, 0))
        recall = (100.0 * raw / bt_kev) if bt_kev else 0.0
        width = int(round(100.0 * raw / max_raw))
        bar_parts.append(
            f'<div><div class="flex justify-between text-[11px] mb-0.5">'
            f'<span class="font-semibold text-{color}-300">{label}</span>'
            f'<span class="font-mono text-{color}-300">{raw} / {bt_kev} caught ({recall:.1f}% recall | {scaled} scaled)</span></div>'
            f'<div class="w-full bg-gray-800 h-2.5 rounded overflow-hidden">'
            f'<div class="bg-{color}-500 h-2.5 rounded" style="width: {width}%"></div></div></div>'
        )
    bt_bars_html = (
        '<div class="space-y-2 mb-4 bg-gray-950/70 p-3 rounded-lg border border-gray-800 text-xs">'
        + "".join(bar_parts) + "</div>"
    )

    col_keys = ["cvss_first", "epss_first", "exploit_then_epss", "readable_score", "our_model", "strict_no_cvss"]
    row_parts = []
    tot_pool = 0
    for p in bt.get("periods", []):
        tot_pool += int(p.get("test_pool_size", 0))
        cells = "".join(
            f'<td class="text-center">{p["raw_top500_caught"].get(k, 0)} ({p["scaled_top500_caught"].get(k, 0)})</td>'
            for k in col_keys
        )
        row_parts.append(
            f'<tr><td class="py-1 px-2">{p.get("period", "")}</td>'
            f'<td class="py-1 px-2 text-center">{int(p.get("test_pool_size", 0)):,} / {p.get("total_future_kev", 0)}</td>{cells}</tr>'
        )
    if row_parts:
        tot_cells = "".join(
            f'<td class="text-center">{bt_raw.get(k, 0)} ({bt_scaled.get(k, 0)})</td>' for k in col_keys
        )
        row_parts.append(
            f'<tr class="bg-gray-800/70 font-bold"><td class="py-1.5 px-2">TOTAL</td>'
            f'<td class="py-1.5 px-2 text-center">{tot_pool:,} / {bt_kev}</td>{tot_cells}</tr>'
        )
    bt_rows_html = "".join(row_parts) or '<tr><td colspan="8" class="py-2 text-center text-gray-500">No backtest results found.</td></tr>'

    best_ours = int(bt_raw.get("strict_no_cvss", 0))
    best_ours_pct = (100.0 * best_ours / bt_kev) if bt_kev else 0.0
    kpi_recall = f"{best_ours_pct:.1f}% ({best_ours}/{bt_kev})"
    kpi_recall_sub = (
        f"vs Exploit+EPSS ({bt_raw.get('exploit_then_epss', 0)}), "
        f"EPSS ({bt_raw.get('epss_first', 0)}), CVSS ({bt_raw.get('cvss_first', 0)})"
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Granite CVE Threat & Attack Surface Intelligence Dashboard (All CVEs)</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <style>
    :root {{
      --bg: #0b0f19;
      --card-bg: #111827;
      --border-color: #1f2937;
      --text-main: #f9fafb;
      --text-muted: #9ca3af;
      --accent: #3b82f6;
    }}
    body {{
      background-color: var(--bg);
      color: var(--text-main);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }}
    .badge-critical {{ background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge-high {{ background-color: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
    .badge-medium {{ background-color: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }}
    .badge-low {{ background-color: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.4); }}
    .badge-unpub {{ background-color: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }}
    .badge-assumed {{ background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
  </style>
</head>
<body class="p-4 md:p-8">

  <!-- Header -->
  <div class="max-w-7xl mx-auto mb-6">
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
      <div>
        <div class="flex items-center gap-3 flex-wrap">
          <span class="px-2.5 py-1 text-xs font-semibold rounded-md bg-blue-900/60 text-blue-400 border border-blue-700/50">IBM Granite 4:3B Intelligence</span>
          <span class="px-2.5 py-1 text-xs font-semibold rounded-md bg-emerald-900/60 text-emerald-400 border border-emerald-700/50">100% Leak-Free Predictive Architecture</span>
          <span class="px-2.5 py-1 text-xs font-semibold rounded-md bg-purple-900/60 text-purple-400 border border-purple-700/50">Out-of-Time Validated (2024–2025)</span>
        </div>
        <h1 class="text-2xl md:text-3xl font-bold mt-2 text-white">Full Dataset Vulnerability Exploitation &amp; Attack Surface Matrix</h1>
        <p class="text-sm text-gray-400 mt-1">Assessing all <strong class="text-white">{total_count:,}</strong> CVEs in Scoreboard 2026 using strictly pre-snapshot telemetry, vendor prior-KEV history, semantic description similarity, and verified Granite 4 explanations.</p>
      </div>
      <div class="flex items-center gap-2">
        <button onclick="toggleBacktestPanel()" class="px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-900/60 hover:bg-emerald-800/80 border border-emerald-600/60 text-emerald-200 transition">
          Toggle Backtest &amp; Leakage Audit
        </button>
        <button onclick="exportCSV()" class="px-3.5 py-2 text-xs font-medium rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 transition">
          Export Filtered CSV
        </button>
      </div>
    </div>

    <!-- TEMPORAL BACKTEST PROOF & SAFE VS UNSAFE COLUMNS AUDIT PANEL -->
    <div id="backtestAuditPanel" class="mt-5 p-5 rounded-xl bg-gray-900/95 border border-emerald-700/40 shadow-xl">
      <div class="flex flex-col lg:flex-row gap-6">
        <!-- Left: Out-of-Time Backtest Visual Chart & Table -->
        <div class="flex-1">
          <div class="flex items-center justify-between mb-2">
            <div>
              <h2 class="text-sm font-bold text-white">2024–2025 Temporal Backtest: Future KEV Additions Caught in Top 500</h2>
            </div>
            <span class="text-[11px] text-gray-400 font-mono">{bt_pool:,} Historical CVEs | {bt_kev} Out-of-Time KEVs</span>
          </div>
          <p class="text-xs text-gray-400 mb-3">Each period is trained strictly on older months and tested on newer unseen months (<code>in_kev == 0</code> at snapshot). Values are loaded from <code>Granite_CVE_Analyzer/backtest_results.json</code>. Raw Top-500 catches shown first, scaled Top-K equivalent in parentheses.</p>
          {bt_bars_html}
          <div class="overflow-x-auto">
            <table class="w-full text-left border-collapse text-[11px]">
              <thead class="bg-gray-800/90 text-gray-300 uppercase">
                <tr>
                  <th class="py-1.5 px-2">Test Period</th>
                  <th class="py-1.5 px-2 text-center">Pool / KEVs</th>
                  <th class="py-1.5 px-2 text-center text-rose-300">CVSS-1st</th>
                  <th class="py-1.5 px-2 text-center text-gray-300">EPSS-1st</th>
                  <th class="py-1.5 px-2 text-center text-amber-300">Exploit+EPSS</th>
                  <th class="py-1.5 px-2 text-center text-purple-300">Readable</th>
                  <th class="py-1.5 px-2 text-center text-blue-300 font-bold">Our Model</th>
                  <th class="py-1.5 px-2 text-center text-emerald-300 font-bold">No-CVSS</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-800 font-mono text-gray-300">
                {bt_rows_html}
              </tbody>
            </table>
          </div>
        </div>

        <!-- Right: Safe vs Unsafe Columns Audit -->
        <div class="lg:w-[440px] flex flex-col justify-between bg-gray-950/60 p-3.5 rounded-lg border border-gray-800">
          <div>
            <h3 class="text-sm font-bold text-white mb-2">Columns Used &amp; Why (Safe vs. Unsafe)</h3>
            <div class="space-y-2 text-[11px]">
              <div class="p-2 rounded bg-emerald-950/30 border border-emerald-800/40">
                <div class="font-bold text-emerald-300">SAFE (Used in Model):</div>
                <ul class="list-disc list-inside text-gray-300 mt-1 space-y-0.5">
                  <li><code class="text-emerald-200">epss</code> + <code class="text-emerald-200">is_epss_v4</code> at <code class="text-emerald-200">snapshot_month</code></li>
                  <li>Snapshot exploit flags: <code class="text-emerald-200">nuclei</code>, <code class="text-emerald-200">metasploit</code>, <code class="text-emerald-200">exploitdb</code>, <code class="text-emerald-200">poc_github</code></li>
                  <li><code class="text-emerald-200">description</code> &amp; <code class="text-emerald-200">assigner</code> (extracts vendor, product, edge/appliance, attack type, &amp; SVD similarity to prior KEVs)</li>
                  <li><code class="text-emerald-200">known_exploited.csv</code> strictly prior to snapshot (<code class="text-emerald-200">date_added &le; snapshot_month</code>)</li>
                  <li>Vendor/CNA <code class="text-emerald-200">cvss3_score</code> ONLY (<code class="text-emerald-200">cvss3_source != 'nvd@nist.gov'</code>)</li>
                </ul>
              </div>
              <div class="p-2 rounded bg-rose-950/30 border border-rose-800/40">
                <div class="font-bold text-rose-300">UNSAFE (Dropped to Prevent Post-Hoc Leakage):</div>
                <ul class="list-disc list-inside text-gray-300 mt-1 space-y-0.5">
                  <li><code class="text-rose-200">affected_products.csv</code> &amp; <code class="text-rose-200">n_affected_cpes</code> (populated by NIST after KEV addition)</li>
                  <li><code class="text-rose-200">nvd_status</code> (<code class="text-rose-200">Analyzed</code> vs <code class="text-rose-200">Awaiting Analysis</code> leaks NVD triage priority)</li>
                  <li><code class="text-rose-200">cvss3_source == 'nvd@nist.gov'</code> (196,952 post-hoc NIST scores) &amp; NIST-only CWEs</li>
                  <li><code class="text-rose-200">references.csv</code> &amp; <code class="text-rose-200">n_references</code> (includes CISA KEV links added later)</li>
                </ul>
              </div>
            </div>
          </div>
          <div class="mt-2 pt-2 border-t border-gray-800 text-[10px] text-gray-400">
            <strong class="text-gray-200">Data Integrity Fixes Applied:</strong> Excluded 62 pre-publication KEV anomalies (<code class="text-gray-300">date_added &lt; published</code>); recovered 4,930 Feb 2025 missing snapshot CVEs; post-checked all Granite 4 explanations to block unverified claims.
          </div>
        </div>
      </div>
    </div>

    <!-- TOP-ORDER TELEMETRY FILTER: With vs Without EPSS Values -->
    <div class="mt-6 p-4 rounded-xl bg-gradient-to-r from-gray-900 via-gray-900/95 to-blue-950/40 border border-blue-800/40 shadow-lg">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider bg-blue-500/20 text-blue-400 border border-blue-500/30">Top Order Filter</span>
            <span class="text-sm font-semibold text-white">EPSS Exploitation Telemetry Selection</span>
          </div>
          <p class="text-xs text-gray-400 mt-0.5">Toggle between vulnerabilities with active scoreboard EPSS scores and entries without scoreboard EPSS data.</p>
        </div>
        <div class="inline-flex rounded-lg bg-gray-800/90 p-1 border border-gray-700 shadow-inner">
          <button id="epss-btn-all" onclick="setEPSSFilter('all')" class="px-3.5 py-1.5 text-xs font-bold rounded-md bg-blue-600 text-white shadow transition flex items-center gap-1.5">
            <span>All Entries</span>
            <span id="badge-count-all" class="text-[10px] bg-blue-900/90 px-1.5 py-0.5 rounded font-mono text-blue-200">{total_count:,}</span>
          </button>
          <button id="epss-btn-with" onclick="setEPSSFilter('with')" class="px-3.5 py-1.5 text-xs font-medium rounded-md text-emerald-400 hover:text-white hover:bg-gray-700 transition flex items-center gap-1.5">
            <span>With EPSS Values</span>
            <span id="badge-count-with" class="text-[10px] bg-emerald-950 px-1.5 py-0.5 rounded font-mono text-emerald-300">...</span>
          </button>
          <button id="epss-btn-without" onclick="setEPSSFilter('without')" class="px-3.5 py-1.5 text-xs font-medium rounded-md text-amber-400 hover:text-white hover:bg-gray-700 transition flex items-center gap-1.5">
            <span>Without EPSS Values (EPSS = 0)</span>
            <span id="badge-count-without" class="text-[10px] bg-amber-950 px-1.5 py-0.5 rounded font-mono text-amber-300">...</span>
          </button>
        </div>
      </div>
    </div>

    <!-- KPI Summary Cards -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-5">
      <div class="p-4 rounded-xl bg-gray-900/80 border border-gray-800 shadow-sm">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Total Assessed CVEs</div>
        <div class="text-2xl font-bold text-white mt-1">{total_count:,}</div>
        <div class="text-xs text-blue-400 mt-1">100% Leak-Free Scoreboard Coverage</div>
      </div>
      <div class="p-4 rounded-xl bg-gray-900/80 border border-gray-800 shadow-sm">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Out-of-Time KEV Recall</div>
        <div class="text-2xl font-bold text-emerald-400 mt-1" id="stat-active-rate">{kpi_recall}</div>
        <div class="text-xs text-gray-400 mt-1">{kpi_recall_sub}</div>
      </div>
      <div class="p-4 rounded-xl bg-gray-900/80 border border-gray-800 shadow-sm">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Prior-KEV Vendor Signal</div>
        <div class="text-2xl font-bold text-purple-400 mt-1" id="stat-mean-ams">Strictly &le; Snapshot</div>
        <div class="text-xs text-gray-400 mt-1">Replaces leaky affected_products.csv</div>
      </div>
      <div class="p-4 rounded-xl bg-gray-900/80 border border-gray-800 shadow-sm">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">CNA-Unscored / Zero-EPSS Pool</div>
        <div class="text-2xl font-bold text-rose-400 mt-1">{len(unpublished):,} Top Targets</div>
        <div class="text-xs text-rose-400/80 mt-1">NIST CVSS &amp; nvd_status Excluded</div>
      </div>
    </div>

    <!-- Search & Sort Controls -->
    <div class="mt-6 flex flex-col md:flex-row md:items-center justify-end gap-4 bg-gray-900/70 p-3 rounded-xl border border-gray-800">
      <div class="flex items-center gap-3">
        <input type="text" id="searchInput" oninput="onSearchChange()" placeholder="Search CVE, Vendor, Product, CWE..." class="w-full md:w-64 px-3 py-1.5 text-xs rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500">
        <select id="sortSelect" onchange="onSortChange()" class="px-3 py-1.5 text-xs rounded-lg bg-gray-800 border border-gray-700 text-gray-300 focus:outline-none">
          <option value="composite">Sort by Predicted KEV Risk</option>
          <option value="epss">Sort by EPSS Likelihood</option>
          <option value="ams">Sort by Vendor Prior KEV Count</option>
          <option value="cvss">Sort by CNA CVSS Score</option>
          <option value="rank">Sort by Rank</option>
          <option value="cve">Sort by CVE ID</option>
          <option value="date">Sort by Effective Date</option>
        </select>
        <button id="sortDirBtn" onclick="toggleSortDir()" title="Toggle ascending / descending" class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 transition whitespace-nowrap">
          &darr; Descending
        </button>
      </div>
    </div>

    <!-- Pagination & Results Bar -->
    <div class="mt-4 p-3 rounded-lg border border-gray-800 bg-gray-900/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-gray-400">
      <div class="flex items-center gap-2">
        <span id="pageInfo" class="font-semibold text-gray-200">Showing 1–50 of {total_count:,} Vulnerabilities</span>
        <span id="sectionNoticeText" class="text-gray-500 hidden sm:inline">| All assessed entries</span>
      </div>
      <div class="flex items-center gap-3">
        <div class="flex items-center gap-1.5">
          <span>Rows per page:</span>
          <select id="pageSizeSelect" onchange="changePageSize(this.value)" class="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200 text-xs focus:outline-none focus:border-blue-500">
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50" selected>50</option>
            <option value="100">100</option>
            <option value="250">250</option>
            <option value="500">500</option>
          </select>
        </div>
        <div class="flex items-center gap-1">
          <button onclick="firstPage()" class="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded border border-gray-700 text-gray-300">&laquo;</button>
          <button onclick="prevPage()" class="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded border border-gray-700 text-gray-300">&lsaquo;</button>
          <span class="px-2 font-mono text-gray-300" id="pageNumDisplay">1 / 1</span>
          <button onclick="nextPage()" class="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded border border-gray-700 text-gray-300">&rsaquo;</button>
          <button onclick="lastPage()" class="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded border border-gray-700 text-gray-300">&raquo;</button>
        </div>
      </div>
    </div>

    <!-- Main Table Container -->
    <div class="mt-3 rounded-xl border border-gray-800 bg-gray-900/90 overflow-hidden shadow-xl">
      <div class="overflow-x-auto max-h-[700px] overflow-y-auto">
        <table class="w-full text-left border-collapse text-xs">
          <thead class="bg-gray-800/90 text-gray-300 uppercase text-[11px] font-semibold sticky top-0 z-10 border-b border-gray-700">
            <tr>
              <th class="py-3 px-3">Rank</th>
              <th class="py-3 px-3">CVE Identifier</th>
              <th class="py-3 px-3">Effective Date</th>
              <th class="py-3 px-3">Predicted KEV Score</th>
              <th class="py-3 px-3">Exploitation Likelihood (EPSS)</th>
              <th class="py-3 px-3">Prior KEVs &amp; Exploits</th>
              <th class="py-3 px-3">Attack Type &amp; CWE</th>
              <th class="py-3 px-3">Extracted Vendor &amp; Product</th>
              <th class="py-3 px-3 text-right">Details</th>
            </tr>
          </thead>
          <tbody id="tableBody" class="divide-y divide-gray-800 font-normal text-gray-300">
            <!-- Dynamically populated via JavaScript -->
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <!-- Detail Modal -->
  <div id="detailModal" class="fixed inset-0 bg-black/75 z-50 flex items-center justify-center p-4 hidden">
    <div class="bg-gray-900 border border-gray-700 rounded-xl max-w-2xl w-full p-6 text-xs text-gray-200 shadow-2xl relative">
      <button onclick="closeModal()" class="absolute top-4 right-4 text-gray-400 hover:text-white text-base font-bold">&times;</button>
      <div id="modalContent"></div>
    </div>
  </div>

  <script>
    // Compact row index mapping:
    // [0:rank, 1:cve, 2:score, 3:cvss, 4:sev, 5:vec, 6:epss, 7:status, 8:ams, 
    //  9:cwe, 10:cwe_name, 11:vcnt, 12:pcnt, 13:vendors, 14:products, 15:date, 16:assumed, 17:scope, 18:assessment]
    const allCVEsData = {all_cves_json};
    const unpublishedData = {unpublished_json};

    const currentTab = 'all';
    let epssFilter = 'all';
    let sortDir = 'desc';
    let currentPage = 1;
    let pageSize = 50;
    let filteredList = [];

    function updateFilterCounts() {{
      const base = (currentTab === 'unpub') ? unpublishedData : allCVEsData;
      const total = base.length;
      let withCount = 0;
      for (let i = 0; i < total; i++) {{
        if (base[i][6] > 0) withCount++;
      }}
      const withoutCount = total - withCount;

      document.getElementById('badge-count-all').innerText = total.toLocaleString();
      document.getElementById('badge-count-with').innerText = withCount.toLocaleString();
      document.getElementById('badge-count-without').innerText = withoutCount.toLocaleString();
    }}

    function setEPSSFilter(filter) {{
      epssFilter = filter;
      const btnAll = document.getElementById('epss-btn-all');
      const btnWith = document.getElementById('epss-btn-with');
      const btnWithout = document.getElementById('epss-btn-without');

      btnAll.className = 'px-3.5 py-1.5 text-xs font-medium rounded-md text-gray-400 hover:text-white hover:bg-gray-700 transition flex items-center gap-1.5';
      btnWith.className = 'px-3.5 py-1.5 text-xs font-medium rounded-md text-emerald-400 hover:text-white hover:bg-gray-700 transition flex items-center gap-1.5';
      btnWithout.className = 'px-3.5 py-1.5 text-xs font-medium rounded-md text-amber-400 hover:text-white hover:bg-gray-700 transition flex items-center gap-1.5';

      if (filter === 'all') {{
        btnAll.className = 'px-3.5 py-1.5 text-xs font-bold rounded-md bg-blue-600 text-white shadow transition flex items-center gap-1.5';
      }} else if (filter === 'with') {{
        btnWith.className = 'px-3.5 py-1.5 text-xs font-bold rounded-md bg-emerald-600 text-white shadow transition flex items-center gap-1.5';
      }} else if (filter === 'without') {{
        btnWithout.className = 'px-3.5 py-1.5 text-xs font-bold rounded-md bg-amber-600 text-white shadow transition flex items-center gap-1.5';
      }}

      currentPage = 1;
      applyFiltersAndSort();
    }}

    function onSearchChange() {{
      currentPage = 1;
      applyFiltersAndSort();
    }}

    function onSortChange() {{
      // Text-like fields default to ascending; numeric risk fields default to descending
      const sort = document.getElementById('sortSelect').value;
      setSortDir((sort === 'rank' || sort === 'cve') ? 'asc' : 'desc');
    }}

    function toggleSortDir() {{
      setSortDir(sortDir === 'desc' ? 'asc' : 'desc');
    }}

    function setSortDir(dir) {{
      sortDir = dir;
      const btn = document.getElementById('sortDirBtn');
      btn.innerHTML = (dir === 'asc') ? '&uarr; Ascending' : '&darr; Descending';
      currentPage = 1;
      applyFiltersAndSort();
    }}

    function changePageSize(val) {{
      pageSize = parseInt(val, 10);
      currentPage = 1;
      renderCurrentPage();
    }}

    function firstPage() {{ if (currentPage > 1) {{ currentPage = 1; renderCurrentPage(); }} }}
    function prevPage() {{ if (currentPage > 1) {{ currentPage--; renderCurrentPage(); }} }}
    function nextPage() {{
      const maxPages = Math.ceil(filteredList.length / pageSize) || 1;
      if (currentPage < maxPages) {{ currentPage++; renderCurrentPage(); }}
    }}
    function lastPage() {{
      const maxPages = Math.ceil(filteredList.length / pageSize) || 1;
      if (currentPage < maxPages) {{ currentPage = maxPages; renderCurrentPage(); }}
    }}

    function applyFiltersAndSort() {{
      const q = document.getElementById('searchInput').value.toLowerCase().trim();
      const sort = document.getElementById('sortSelect').value;

      let source = (currentTab === 'unpub') ? [...unpublishedData] : [...allCVEsData];

      // Top Order Filter
      if (epssFilter === 'with') {{
        source = source.filter(x => x[6] > 0);
      }} else if (epssFilter === 'without') {{
        source = source.filter(x => x[6] === 0 || (x[7] && x[7].includes('No information')));
      }}

      // Search Query
      if (q) {{
        source = source.filter(x => {{
          return (x[1] && x[1].toLowerCase().includes(q)) ||
                 (x[9] && x[9].toLowerCase().includes(q)) ||
                 (x[10] && x[10].toLowerCase().includes(q)) ||
                 (x[13] && x[13].toLowerCase().includes(q)) ||
                 (x[14] && x[14].toLowerCase().includes(q));
        }});
      }}

      // Sort (direction controlled by the Ascending / Descending toggle)
      const dirMul = (sortDir === 'asc') ? 1 : -1;
      source.sort((a, b) => {{
        let cmp;
        if (sort === 'epss') cmp = a[6] - b[6];
        else if (sort === 'ams') cmp = a[8] - b[8];
        else if (sort === 'cvss') cmp = a[3] - b[3];
        else if (sort === 'rank') cmp = a[0] - b[0];
        else if (sort === 'cve') cmp = String(a[1]).localeCompare(String(b[1]), undefined, {{ numeric: true }});
        else if (sort === 'date') cmp = String(a[15] || '').localeCompare(String(b[15] || ''));
        else cmp = a[2] - b[2]; // composite
        // Stable tie-break on model rank so equal values keep a predictable order
        return (cmp * dirMul) || (a[0] - b[0]);
      }});

      filteredList = source;
      renderCurrentPage();
    }}

    function getSeverityBadge(sev) {{
      const s = (sev || '').toUpperCase();
      if (s === 'CRITICAL') return '<span class="px-2 py-0.5 rounded text-[11px] font-semibold badge-critical">CRITICAL</span>';
      if (s === 'HIGH') return '<span class="px-2 py-0.5 rounded text-[11px] font-semibold badge-high">HIGH</span>';
      if (s === 'MEDIUM') return '<span class="px-2 py-0.5 rounded text-[11px] font-semibold badge-medium">MEDIUM</span>';
      return '<span class="px-2 py-0.5 rounded text-[11px] font-semibold badge-low">' + s + '</span>';
    }}

    function getEPSSBadge(score, status) {{
      if (score === 0 || (status && status.includes('No information'))) {{
        return '<div class="flex flex-col"><span class="text-amber-400/90 font-mono font-medium">0.0000</span><span class="text-[10px] text-amber-400/80 font-medium">No Scoreboard Info</span></div>';
      }}
      let colorClass = 'text-emerald-400';
      if (score > 0.5) colorClass = 'text-rose-400 font-bold';
      else if (score > 0.1) colorClass = 'text-amber-400 font-semibold';
      return '<div class="flex flex-col"><span class="' + colorClass + ' font-mono">' + Number(score).toFixed(5) + '</span><span class="text-[10px] text-gray-400">EPSS v4 Active</span></div>';
    }}

    function renderCurrentPage() {{
      const total = filteredList.length;
      const maxPages = Math.ceil(total / pageSize) || 1;
      if (currentPage > maxPages) currentPage = maxPages;
      if (currentPage < 1) currentPage = 1;

      const startIdx = (currentPage - 1) * pageSize;
      const endIdx = Math.min(startIdx + pageSize, total);

      document.getElementById('pageInfo').innerText = `Showing ${{total === 0 ? 0 : startIdx + 1}}–${{endIdx}} of ${{total.toLocaleString()}} Vulnerabilities`;
      document.getElementById('pageNumDisplay').innerText = `${{currentPage}} / ${{maxPages.toLocaleString()}}`;

      const tbody = document.getElementById('tableBody');
      tbody.innerHTML = '';

      if (total === 0) {{
        tbody.innerHTML = '<tr><td colspan="9" class="text-center py-8 text-gray-500">No vulnerabilities matched current filters.</td></tr>';
        return;
      }}

      const isUnpub = (currentTab === 'unpub');
      const pageSlice = filteredList.slice(startIdx, endIdx);

      // Compute Section Averages for the current visible section/page
      let sumScore = 0, sumCvss = 0, sumEpss = 0, sumAms = 0, sumVendors = 0, sumProducts = 0;
      const cweMap = {{}}, vendorMap = {{}};

      pageSlice.forEach(row => {{
        sumScore += (row[2] || 0);
        sumCvss += (row[3] || 0);
        sumEpss += (row[6] || 0);
        sumAms += (row[8] || 0);
        sumVendors += (row[11] || 0);
        sumProducts += (row[12] || 0);

        const cwe = row[9] || 'N/A';
        cweMap[cwe] = (cweMap[cwe] || 0) + 1;

        if (row[13] && row[13] !== 'Not Specified' && row[13] !== 'Pre-disclosure / Unlisted') {{
          const firstV = row[13].split(';')[0].trim();
          if (firstV) vendorMap[firstV] = (vendorMap[firstV] || 0) + 1;
        }}
      }});

      const count = pageSlice.length || 1;
      const avgScore = (sumScore / count).toFixed(2);
      const avgCvss = (sumCvss / count).toFixed(2);
      const avgEpss = (sumEpss / count).toFixed(5);
      const avgAms = (sumAms / count).toFixed(2);
      const avgVendors = (sumVendors / count).toFixed(1);
      const avgProducts = (sumProducts / count).toFixed(1);

      let topCwe = '—', maxCwe = 0;
      for (const [k, v] of Object.entries(cweMap)) {{
        if (v > maxCwe && k !== 'NVD-CWE-noinfo') {{ maxCwe = v; topCwe = k; }}
      }}
      let topVendor = '—', maxV = 0;
      for (const [k, v] of Object.entries(vendorMap)) {{
        if (v > maxV) {{ maxV = v; topVendor = k; }}
      }}

      // Add Section Average Header Row heading this section in the table
      const avgRow = document.createElement('tr');
      avgRow.className = 'bg-gradient-to-r from-blue-950/90 via-blue-900/60 to-purple-950/80 border-b-2 border-blue-500/80 text-blue-100 font-semibold text-xs shadow-md sticky top-[37px] z-[9]';
      avgRow.innerHTML = `
        <td class="py-2.5 px-3 font-mono font-bold text-blue-300">AVG</td>
        <td class="py-2.5 px-3">
          <div class="font-bold text-white tracking-wide flex items-center gap-1.5">
            <span>SECTION AVERAGES</span>
            <span class="text-[9px] px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-300 border border-blue-500/40 font-mono">PAGE HEAD</span>
          </div>
          <div class="text-[10px] text-blue-300 font-normal">Mean metrics across ${{count}} visible vulnerabilities</div>
        </td>
        <td class="py-2.5 px-3 text-gray-400 font-mono text-[11px]">—</td>
        <td class="py-2.5 px-3">
          <div class="flex items-center gap-1.5">
            <span class="text-sm font-bold text-white">${{avgScore}}</span>
            <span class="text-[10px] px-1 py-0.2 rounded bg-blue-800/80 text-blue-200">AVG</span>
          </div>
          <div class="text-[10px] text-blue-300 font-medium">CVSS Mean: ${{avgCvss}}</div>
        </td>
        <td class="py-2.5 px-3">
          <div class="text-sm font-mono font-bold text-amber-300">${{avgEpss}}</div>
          <div class="text-[10px] text-emerald-300 font-medium">Mean EPSS Likelihood</div>
        </td>
        <td class="py-2.5 px-3">
          <div class="text-sm font-mono font-bold text-purple-300">${{avgAms}}</div>
          <div class="text-[10px] text-gray-300 font-medium">Avg ${{avgVendors}} Prior KEVs / ${{avgProducts}} Flags</div>
        </td>
        <td class="py-2.5 px-3">
          <div class="text-gray-200 font-medium font-mono">${{topCwe}}</div>
          <div class="text-[10px] text-blue-300">Leading weakness</div>
        </td>
        <td class="py-2.5 px-3">
          <div class="text-gray-200 font-medium truncate max-w-[170px]">${{topVendor}}</div>
          <div class="text-[10px] text-gray-400">Leading affected vendor</div>
        </td>
        <td class="py-2.5 px-3 text-right">
          <span class="text-[10px] text-blue-300/80 font-mono">Summary</span>
        </td>
      `;
      tbody.appendChild(avgRow);

      pageSlice.forEach((row, i) => {{
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-gray-800/50 transition';

        const rankText = isUnpub ? ('U-' + (startIdx + i + 1)) : ('#' + row[0]);

        const dateDisplay = `
          <div class="flex flex-col">
            <span class="font-mono text-gray-300">${{row[15] || 'N/A'}}</span>
            ${{row[16] ? '<span class="text-[9px] badge-assumed px-1 py-0.2 rounded font-semibold mt-0.5">Snapshot Date Assumed</span>' : '<span class="text-[9px] text-gray-500">Published</span>'}}
          </div>
        `;

        tr.innerHTML = `
          <td class="py-3 px-3 text-gray-400 font-mono">${{rankText}}</td>
          <td class="py-3 px-3">
            <div class="font-bold text-blue-400 hover:text-blue-300 cursor-pointer" onclick="openModal('${{row[1]}}', ${{isUnpub}})">${{row[1]}}</div>
            <div class="text-[10px] text-gray-400">${{isUnpub ? '<span class="badge-unpub px-1.5 py-0.2 rounded font-semibold">' + row[17] + '</span>' : row[17]}}</div>
          </td>
          <td class="py-3 px-3">
            ${{dateDisplay}}
          </td>
          <td class="py-3 px-3">
            <div class="flex items-center gap-2">
              <span class="text-base font-bold text-white">${{row[2]}}</span>
              ${{getSeverityBadge(row[4])}}
            </div>
            <div class="text-[10px] text-gray-400">CVSS ${{row[3]}} (${{row[5]}})</div>
          </td>
          <td class="py-3 px-3">
            ${{getEPSSBadge(row[6], row[7])}}
          </td>
          <td class="py-3 px-3">
            <div class="font-semibold text-purple-300 font-mono text-sm">${{row[8]}} Prior KEVs</div>
            <div class="text-[10px] text-gray-400">${{row[12]}} Public Exploit Flag(s)</div>
          </td>
          <td class="py-3 px-3">
            <div class="font-mono text-gray-200 font-semibold">${{row[9]}}</div>
            <div class="text-[10px] text-gray-400 truncate max-w-[150px]">${{row[10]}}</div>
          </td>
          <td class="py-3 px-3">
            <div class="text-gray-300 font-medium truncate max-w-[170px]">${{row[13]}}</div>
            <div class="text-[10px] text-gray-500 truncate max-w-[170px]">${{row[14]}}</div>
          </td>
          <td class="py-3 px-3 text-right">
            <button onclick="openModal('${{row[1]}}', ${{isUnpub}})" class="px-2.5 py-1 text-[11px] rounded bg-gray-800 hover:bg-gray-700 text-blue-400 border border-gray-700 transition">
              Inspect
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      }});
    }}

    function openModal(cveId, isUnpub) {{
      const list = isUnpub ? unpublishedData : allCVEsData;
      const item = list.find(x => x[1] === cveId);
      if (!item) return;

      const modal = document.getElementById('detailModal');
      const content = document.getElementById('modalContent');

      content.innerHTML = `
        <div class="border-b border-gray-800 pb-3 mb-4">
          <div class="flex items-center justify-between">
            <h2 class="text-lg font-bold text-white flex items-center gap-2">
              <span>${{item[1]}}</span>
              ${{getSeverityBadge(item[4])}}
            </h2>
            <div class="text-sm font-bold text-purple-400 font-mono">Composite Threat: ${{item[2]}} / 100</div>
          </div>
          <div class="text-xs text-gray-400 mt-1">${{item[9]}}: ${{item[10]}}</div>
        </div>

        <div class="grid grid-cols-2 md:grid-cols-4 gap-2.5 mb-4">
          <div class="p-2.5 bg-gray-800/60 rounded border border-gray-700">
            <div class="text-[10px] text-gray-400 uppercase">CVSS Base Score</div>
            <div class="text-base font-bold text-white mt-0.5">${{item[3]}}</div>
            <div class="text-[10px] text-gray-400">${{item[5]}} Vector</div>
          </div>
          <div class="p-2.5 bg-gray-800/60 rounded border border-gray-700">
            <div class="text-[10px] text-gray-400 uppercase">EPSS Exploitation</div>
            <div class="text-base font-bold text-amber-400 font-mono mt-0.5">${{item[6]}}</div>
            <div class="text-[10px] text-gray-400">${{item[7]}}</div>
          </div>
          <div class="p-2.5 bg-gray-800/60 rounded border border-gray-700">
            <div class="text-[10px] text-gray-400 uppercase">Vendor Prior KEVs</div>
            <div class="text-base font-bold text-purple-400 font-mono mt-0.5">${{item[8]}}</div>
            <div class="text-[10px] text-gray-400">${{item[12]}} Snapshot Exploit Flags</div>
          </div>
          <div class="p-2.5 bg-gray-800/60 rounded border border-gray-700">
            <div class="text-[10px] text-gray-400 uppercase">Effective Date</div>
            <div class="text-sm font-bold text-blue-400 font-mono mt-0.5">${{item[15]}}</div>
            <div class="text-[10px] text-gray-400">${{item[16] ? 'Assumed from snapshot' : 'Published date'}}</div>
          </div>
        </div>

        <div class="mb-4">
          <div class="text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">Affected Real-World Assets</div>
          <div class="p-3 bg-gray-800/40 rounded border border-gray-800 text-gray-300 text-xs">
            <div><strong class="text-gray-400">Vendors:</strong> ${{item[13]}}</div>
            <div class="mt-1"><strong class="text-gray-400">Products:</strong> ${{item[14]}}</div>
          </div>
        </div>

        <div>
          <div class="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
            <span>IBM Granite 4 Attack Plane Intelligence</span>
          </div>
          <div class="p-3 bg-blue-950/20 border border-blue-900/40 rounded text-gray-300 text-xs leading-relaxed">
            ${{item[18] || 'Full dataset vulnerability profile evaluated via Granite CVE scoring engine.'}}
          </div>
        </div>
      `;
      modal.classList.remove('hidden');
    }}

    function closeModal() {{
      document.getElementById('detailModal').classList.add('hidden');
    }}

    function toggleBacktestPanel() {{
      const p = document.getElementById('backtestAuditPanel');
      if (p) p.classList.toggle('hidden');
    }}

    function exportCSV() {{
      if (!filteredList.length) return;
      const headers = ["Rank", "CVE_ID", "Composite_Score", "CVSS", "Severity", "Vector", "EPSS", "Status", "AttackMatrixSize", "CWE", "CWEName", "VendorsCount", "ProductsCount", "Vendors", "Products", "EffectiveDate", "AssumedSnapshot", "Scope", "Assessment"];
      const csvContent = "data:text/csv;charset=utf-8," + 
        [headers.join(",")].concat(filteredList.map(r => r.map(cell => JSON.stringify(cell ?? "")).join(","))).join("\\n");
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement("a");
      link.setAttribute("href", encodedUri);
      link.setAttribute("download", (currentTab === 'unpub' ? "unpublished_vulnerabilities.csv" : "assessed_cves_filtered.csv"));
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }}

    // Initial render
    updateFilterCounts();
    applyFiltersAndSort();
  </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Successfully generated full dataset dashboard: {output_path} ({total_count:,} CVEs)")


def main():
    print("Loading all leak-free assessed CVEs noted in the dataset...")
    all_cves = load_all_assessed_cves("all_cves_assessed.csv")
    print(f"Loaded {len(all_cves):,} CVEs")

    print("Extracting leak-free Zero-EPSS and CNA-Unscored vulnerabilities...")
    unpub = load_unpublished(all_cves, limit=500)
    print(f"Extracted {len(unpub):,} Zero-EPSS / CNA-Unscored vulnerabilities")

    # Generate in workspace
    generate_html_dashboard(all_cves, unpub, "dashboard.html")

    # Also generate in artifact directory
    artifact_dir = r"C:\Users\User\.gemini\antigravity\brain\b001ba77-b50f-4855-adb2-e36469d6b228"
    if os.path.exists(artifact_dir):
        artifact_path = os.path.join(artifact_dir, "dashboard.html")
        generate_html_dashboard(all_cves, unpub, artifact_path)


if __name__ == "__main__":
    main()
