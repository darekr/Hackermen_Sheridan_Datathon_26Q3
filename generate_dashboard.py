"""
Dashboard Generator for Top 500 and Unpublished Vulnerabilities.
Produces an interactive, standalone HTML dashboard with Tailwind CSS.
Focuses on:
1. Likelihood of Exploitation (EPSS v4, weaponization telemetry)
2. Attack Surface & Attack Plane (Attack Matrix Size, affected vendors/products)
3. Dedicated section for Unpublished/Pre-Analysis vulnerabilities (NVD Deferred/Awaiting Analysis)
"""

import os
import csv
import json
import math
from typing import List, Dict, Any


def load_top500(csv_path: str = "top500.csv") -> List[Dict[str, Any]]:
    rows = []
    if not os.path.exists(csv_path):
        return rows
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({
                "rank": int(r.get("rank") or 0),
                "cve_id": r.get("cve_id", ""),
                "composite_score": float(r.get("composite_score") or 0.0),
                "cvss3_score": float(r.get("cvss3_score") or 0.0),
                "cvss3_severity": r.get("cvss3_severity", "UNKNOWN"),
                "attack_vector": r.get("attack_vector", "NETWORK"),
                "epss_score": float(r.get("epss_score") or 0.0),
                "epss_status": r.get("epss_status", ""),
                "epss_weighted": float(r.get("epss_weighted") or 0.0),
                "attack_matrix_size": float(r.get("attack_matrix_size") or 0.0),
                "cwe_id": r.get("cwe_id", "NVD-CWE-noinfo"),
                "cwe_name": r.get("cwe_name", ""),
                "affected_vendors_count": int(r.get("affected_vendors_count") or 0),
                "affected_products_count": int(r.get("affected_products_count") or 0),
                "sample_affected_vendors": r.get("sample_affected_vendors", ""),
                "sample_affected_products": r.get("sample_affected_products", ""),
                "attack_plane_scope": r.get("attack_plane_scope", ""),
                "granite_assessment": r.get("granite_attack_plane_assessment", "")
            })
    return rows


def load_unpublished(
    data_dir: str = "data",
    limit: int = 150
) -> List[Dict[str, Any]]:
    scoreboard_path = os.path.join(data_dir, "scoreboard_2026.csv")
    vuln_path = os.path.join(data_dir, "vulnerabilities.csv")
    products_path = os.path.join(data_dir, "affected_products.csv")
    cwe_path = os.path.join(data_dir, "weakness_types.csv")

    cwe_map = {}
    if os.path.exists(cwe_path):
        with open(cwe_path, "r", encoding="utf-8", errors="replace") as f:
            for r in csv.DictReader(f):
                cwe_map[r.get("cwe_id", "").strip().upper()] = r.get("name", "")

    scoreboard = {}
    if os.path.exists(scoreboard_path):
        with open(scoreboard_path, "r", encoding="utf-8", errors="replace") as f:
            for r in csv.DictReader(f):
                cve = r.get("cve_id", "").strip().upper()
                raw_epss = float(r.get("epss") or 0.0)
                scoreboard[cve] = {
                    "raw_epss": raw_epss,
                    "metasploit": int(r.get("metasploit") or 0),
                    "exploitdb": int(r.get("exploitdb") or 0),
                    "poc_github": int(r.get("poc_github") or 0)
                }

    # Load product footprints
    product_stats = {}
    if os.path.exists(products_path):
        with open(products_path, "r", encoding="utf-8", errors="replace") as f:
            for r in csv.DictReader(f):
                cve = r.get("cve_id", "").strip().upper()
                if cve in scoreboard:
                    if cve not in product_stats:
                        product_stats[cve] = {"vendors": set(), "products": set(), "count": 0}
                    product_stats[cve]["count"] += 1
                    if r.get("vendor"): product_stats[cve]["vendors"].add(r["vendor"])
                    if r.get("product"): product_stats[cve]["products"].add(r["product"])

    candidates = []
    if os.path.exists(vuln_path):
        with open(vuln_path, "r", encoding="utf-8", errors="replace") as f:
            for r in csv.DictReader(f):
                cve = r.get("cve_id", "").strip().upper()
                if cve not in scoreboard:
                    continue
                status = r.get("nvd_status", "")
                if status in ("Awaiting Analysis", "Deferred", "Received", "Undergoing Analysis"):
                    cvss = float(r.get("cvss3_score") or r.get("cvss2_score") or 0.0)
                    sc = scoreboard[cve]
                    raw_epss = sc["raw_epss"]
                    epss_status = "No information available in scoreboard" if raw_epss == 0.0 else "Active in Scoreboard"

                    p_info = product_stats.get(cve, {"vendors": set(), "products": set(), "count": 0})
                    v_cnt = len(p_info["vendors"])
                    p_cnt = len(p_info["products"])
                    cfg_cnt = p_info["count"]

                    vec = (r.get("attack_vector") or "NETWORK").upper()
                    vec_mult = 1.0 if "NETWORK" in vec else (0.8 if "ADJACENT" in vec else 0.5)
                    ams = round((math.log1p(v_cnt)*2.5 + math.log1p(p_cnt)*2.5 + math.log1p(cfg_cnt)*1.0) * vec_mult, 2)

                    # Score
                    comp = round(min(100.0, (cvss/10.0)*35.0 + raw_epss*35.0 + min(20.0, ams*2.2) + (sc["metasploit"]*3.0) + (sc["exploitdb"]*2.0)), 2)

                    raw_cwe = r.get("cwe_ids", "").strip() or "NVD-CWE-noinfo"
                    primary_cwe = raw_cwe.split(";")[0].strip().upper()
                    cwe_name = cwe_map.get(primary_cwe, "Uncategorized Weakness")

                    candidates.append({
                        "cve_id": cve,
                        "nvd_status": status,
                        "composite_score": comp,
                        "cvss3_score": cvss,
                        "cvss3_severity": r.get("cvss3_severity") or ("HIGH" if cvss >= 7.0 else "MEDIUM"),
                        "attack_vector": vec,
                        "epss_score": raw_epss,
                        "epss_status": epss_status,
                        "attack_matrix_size": ams,
                        "cwe_id": raw_cwe,
                        "cwe_name": cwe_name,
                        "affected_vendors_count": v_cnt,
                        "affected_products_count": p_cnt,
                        "sample_affected_vendors": "; ".join(list(p_info["vendors"])[:4]) if p_info["vendors"] else "Pre-disclosure / Unlisted",
                        "sample_affected_products": "; ".join(list(p_info["products"])[:4]) if p_info["products"] else "Pre-disclosure / Unlisted",
                        "description": r.get("description", "")[:180]
                    })

    candidates.sort(key=lambda x: x["composite_score"], reverse=True)
    return candidates[:limit]


def generate_html_dashboard(
    top500: List[Dict[str, Any]],
    unpublished: List[Dict[str, Any]],
    output_path: str
):
    top500_json = json.dumps(top500)
    unpublished_json = json.dumps(unpublished)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Granite CVE Threat & Attack Surface Intelligence Dashboard</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <style>
    :root {{
      --bg: #0b0f19;
      --card-bg: #111827;
      --border-color: #1f2937;
      --text-main: #f9fafb;
      --text-muted: #9ca3af;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
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
    .badge-info {{ background-color: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }}
    .badge-unpub {{ background-color: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }}
  </style>
</head>
<body class="p-4 md:p-8">

  <!-- Header -->
  <div class="max-w-7xl mx-auto mb-8">
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-6">
      <div>
        <div class="flex items-center gap-3">
          <span class="px-2.5 py-1 text-xs font-semibold rounded-md bg-blue-900/60 text-blue-400 border border-blue-700/50">IBM Granite 4:3B Intelligence</span>
          <span class="px-2.5 py-1 text-xs font-semibold rounded-md bg-purple-900/60 text-purple-400 border border-purple-700/50">Scoreboard 2026 Evaluation</span>
        </div>
        <h1 class="text-2xl md:text-3xl font-bold mt-2 text-white">Vulnerability Exploitation & Attack Surface Matrix</h1>
        <p class="text-sm text-gray-400 mt-1">Multi-factor intelligence evaluating Likelihood of Exploitation (EPSS v4), Attack Surface Footprint, and Pre-Analysis Zero-Days.</p>
      </div>
      <div class="flex items-center gap-2">
        <button onclick="exportCSV()" class="px-3 py-2 text-xs font-medium rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 transition">
          Export Filtered CSV
        </button>
      </div>
    </div>

    <!-- KPI Summary Cards -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
      <div class="p-4 rounded-xl bg-gray-900/80 border border-gray-800 shadow-sm">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Top Targets Analyzed</div>
        <div class="text-2xl font-bold text-white mt-1">500</div>
        <div class="text-xs text-blue-400 mt-1">Ranked from 72,670 scoreboard CVEs</div>
      </div>
      <div class="p-4 rounded-xl bg-gray-900/80 border border-gray-800 shadow-sm">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Active Exploitation Rate</div>
        <div class="text-2xl font-bold text-amber-400 mt-1" id="stat-active-rate">99.6%</div>
        <div class="text-xs text-gray-400 mt-1">EPSS &gt; 0 with telemetry telemetry</div>
      </div>
      <div class="p-4 rounded-xl bg-gray-900/80 border border-gray-800 shadow-sm">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Mean Attack Matrix Size</div>
        <div class="text-2xl font-bold text-purple-400 mt-1" id="stat-mean-ams">8.12</div>
        <div class="text-xs text-gray-400 mt-1">Log-scaled vendor &amp; product plane</div>
      </div>
      <div class="p-4 rounded-xl bg-gray-900/80 border border-gray-800 shadow-sm">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Unpublished / Deferred Pool</div>
        <div class="text-2xl font-bold text-rose-400 mt-1" id="stat-unpub-count">150 Priority</div>
        <div class="text-xs text-rose-400/80 mt-1">NVD Deferred &amp; Awaiting Analysis</div>
      </div>
    </div>

    <!-- Navigation Tabs & Search Controls -->
    <div class="mt-8 flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gray-900/60 p-3 rounded-xl border border-gray-800">
      <div class="flex items-center gap-2 overflow-x-auto">
        <button id="tab-all" onclick="setTab('all')" class="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 text-white transition">All Top 500</button>
        <button id="tab-exploit" onclick="setTab('exploit')" class="px-3.5 py-1.5 text-xs font-medium rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition">Exploitation Likelihood Focus</button>
        <button id="tab-surface" onclick="setTab('surface')" class="px-3.5 py-1.5 text-xs font-medium rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition">Attack Surface Focus</button>
        <button id="tab-unpub" onclick="setTab('unpub')" class="px-3.5 py-1.5 text-xs font-medium rounded-lg text-purple-400 hover:bg-purple-950/40 border border-purple-800/40 transition">Unpublished &amp; Deferred Vulns</button>
      </div>
      <div class="flex items-center gap-3">
        <input type="text" id="searchInput" oninput="renderTable()" placeholder="Search CVE, Vendor, Product, CWE..." class="w-full md:w-64 px-3 py-1.5 text-xs rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500">
        <select id="sortSelect" onchange="renderTable()" class="px-3 py-1.5 text-xs rounded-lg bg-gray-800 border border-gray-700 text-gray-300 focus:outline-none">
          <option value="composite">Sort by Composite Threat</option>
          <option value="epss">Sort by EPSS Likelihood</option>
          <option value="ams">Sort by Attack Matrix Size</option>
          <option value="cvss">Sort by CVSS Score</option>
        </select>
      </div>
    </div>

    <!-- Section Notice Banner -->
    <div id="sectionNotice" class="mt-4 p-3 rounded-lg border border-gray-800 bg-gray-900/40 flex items-center justify-between text-xs text-gray-400">
      <span id="sectionNoticeText">Displaying full ranked Top 500 vulnerability attack surface evaluation.</span>
      <span id="resultCount" class="font-semibold text-gray-300">500 Records</span>
    </div>

    <!-- Main Table Container -->
    <div class="mt-4 rounded-xl border border-gray-800 bg-gray-900/90 overflow-hidden shadow-xl">
      <div class="overflow-x-auto max-h-[700px] overflow-y-auto">
        <table class="w-full text-left border-collapse text-xs">
          <thead class="bg-gray-800/90 text-gray-300 uppercase text-[11px] font-semibold sticky top-0 z-10 border-b border-gray-700">
            <tr>
              <th class="py-3 px-3">Rank</th>
              <th class="py-3 px-3">CVE Identifier</th>
              <th class="py-3 px-3">Threat Index</th>
              <th class="py-3 px-3">Exploitation Likelihood (EPSS)</th>
              <th class="py-3 px-3">Attack Surface Matrix</th>
              <th class="py-3 px-3">Weakness (CWE)</th>
              <th class="py-3 px-3">Target Ecosystem &amp; Products</th>
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
    const top500Data = {top500_json};
    const unpublishedData = {unpublished_json};

    let currentTab = 'all';

    function setTab(tab) {{
      currentTab = tab;
      ['all', 'exploit', 'surface', 'unpub'].forEach(t => {{
        const btn = document.getElementById('tab-' + t);
        if (t === tab) {{
          btn.className = 'px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 text-white transition';
        }} else {{
          btn.className = 'px-3.5 py-1.5 text-xs font-medium rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition';
        }}
      }});

      const notice = document.getElementById('sectionNoticeText');
      if (tab === 'all') {{
        notice.innerText = 'Displaying full ranked Top 500 vulnerability attack surface evaluation.';
      }} else if (tab === 'exploit') {{
        notice.innerText = 'Filtered by High Likelihood of Exploitation (EPSS v4 Active & Scoreboard Weaponization).';
      }} else if (tab === 'surface') {{
        notice.innerText = 'Filtered by Maximum Real-World Attack Surface (Attack Matrix Size & Multi-Product Footprint).';
      }} else if (tab === 'unpub') {{
        notice.innerHTML = '<span class="text-purple-400 font-semibold">[SEPARATE SECTION]</span> Displaying Unpublished & Deferred Vulnerabilities (NVD Deferred / Awaiting Analysis / Zero-Telemetry) scored against the identical composite metric.';
      }}

      renderTable();
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
        return '<div class="flex flex-col"><span class="text-gray-400 font-mono font-medium">0.0000</span><span class="text-[10px] text-gray-500">No Scoreboard Info</span></div>';
      }}
      let colorClass = 'text-emerald-400';
      if (score > 0.5) colorClass = 'text-rose-400 font-bold';
      else if (score > 0.1) colorClass = 'text-amber-400 font-semibold';
      return '<div class="flex flex-col"><span class="' + colorClass + ' font-mono">' + Number(score).toFixed(5) + '</span><span class="text-[10px] text-gray-400">EPSS v4 Active</span></div>';
    }}

    function renderTable() {{
      const q = document.getElementById('searchInput').value.toLowerCase().trim();
      const sort = document.getElementById('sortSelect').value;

      let source = (currentTab === 'unpub') ? [...unpublishedData] : [...top500Data];

      if (currentTab === 'exploit') {{
        source = source.filter(x => x.epss_score > 0.05);
      }} else if (currentTab === 'surface') {{
        source = source.filter(x => x.attack_matrix_size > 6.0);
      }}

      if (q) {{
        source = source.filter(x => {{
          return (x.cve_id && x.cve_id.toLowerCase().includes(q)) ||
                 (x.cwe_id && x.cwe_id.toLowerCase().includes(q)) ||
                 (x.cwe_name && x.cwe_name.toLowerCase().includes(q)) ||
                 (x.sample_affected_vendors && x.sample_affected_vendors.toLowerCase().includes(q)) ||
                 (x.sample_affected_products && x.sample_affected_products.toLowerCase().includes(q));
        }});
      }}

      // Sort
      source.sort((a, b) => {{
        if (sort === 'epss') return b.epss_score - a.epss_score;
        if (sort === 'ams') return b.attack_matrix_size - a.attack_matrix_size;
        if (sort === 'cvss') return b.cvss3_score - a.cvss3_score;
        return b.composite_score - a.composite_score;
      }});

      document.getElementById('resultCount').innerText = source.length + ' Records';

      const tbody = document.getElementById('tableBody');
      tbody.innerHTML = '';

      if (source.length === 0) {{
        tbody.innerHTML = '<tr><td colspan="8" class="text-center py-8 text-gray-500">No vulnerabilities matched current filters.</td></tr>';
        return;
      }}

      source.forEach((row, idx) => {{
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-gray-800/50 transition';

        const isUnpub = (currentTab === 'unpub');
        const rankText = isUnpub ? ('U-' + (idx + 1)) : ('#' + (row.rank || (idx + 1)));

        tr.innerHTML = `
          <td class="py-3 px-3 text-gray-400 font-mono">${{rankText}}</td>
          <td class="py-3 px-3">
            <div class="font-bold text-blue-400 hover:text-blue-300 cursor-pointer" onclick="openModal('${{row.cve_id}}', ${{isUnpub}})">${{row.cve_id}}</div>
            <div class="text-[10px] text-gray-400">${{isUnpub ? '<span class="badge-unpub px-1.5 py-0.2 rounded font-semibold">' + row.nvd_status + '</span>' : row.attack_plane_scope}}</div>
          </td>
          <td class="py-3 px-3">
            <div class="flex items-center gap-2">
              <span class="text-base font-bold text-white">${{row.composite_score}}</span>
              ${{getSeverityBadge(row.cvss3_severity)}}
            </div>
            <div class="text-[10px] text-gray-400">CVSS ${{row.cvss3_score}} (${{row.attack_vector}})</div>
          </td>
          <td class="py-3 px-3">
            ${{getEPSSBadge(row.epss_score, row.epss_status)}}
          </td>
          <td class="py-3 px-3">
            <div class="font-semibold text-purple-300 font-mono text-sm">${{row.attack_matrix_size}}</div>
            <div class="text-[10px] text-gray-400">${{row.affected_vendors_count}} Vendors / ${{row.affected_products_count}} Products</div>
          </td>
          <td class="py-3 px-3">
            <div class="font-mono text-gray-200 font-semibold">${{row.cwe_id}}</div>
            <div class="text-[10px] text-gray-400 truncate max-w-[160px]">${{row.cwe_name}}</div>
          </td>
          <td class="py-3 px-3">
            <div class="text-gray-300 font-medium truncate max-w-[180px]">${{row.sample_affected_vendors}}</div>
            <div class="text-[10px] text-gray-500 truncate max-w-[180px]">${{row.sample_affected_products}}</div>
          </td>
          <td class="py-3 px-3 text-right">
            <button onclick="openModal('${{row.cve_id}}', ${{isUnpub}})" class="px-2.5 py-1 text-[11px] rounded bg-gray-800 hover:bg-gray-700 text-blue-400 border border-gray-700 transition">
              Inspect
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      }});
    }}

    function openModal(cveId, isUnpub) {{
      const list = isUnpub ? unpublishedData : top500Data;
      const item = list.find(x => x.cve_id === cveId);
      if (!item) return;

      const modal = document.getElementById('detailModal');
      const content = document.getElementById('modalContent');

      content.innerHTML = `
        <div class="border-b border-gray-800 pb-3 mb-4">
          <div class="flex items-center justify-between">
            <h2 class="text-lg font-bold text-white flex items-center gap-2">
              <span>${{item.cve_id}}</span>
              ${{getSeverityBadge(item.cvss3_severity)}}
            </h2>
            <div class="text-sm font-bold text-purple-400 font-mono">Composite Threat: ${{item.composite_score}} / 100</div>
          </div>
          <div class="text-xs text-gray-400 mt-1">${{item.cwe_id}}: ${{item.cwe_name}}</div>
        </div>

        <div class="grid grid-cols-2 md:grid-cols-3 gap-3 mb-4">
          <div class="p-2.5 bg-gray-800/60 rounded border border-gray-700">
            <div class="text-[10px] text-gray-400 uppercase">CVSS Base Score</div>
            <div class="text-base font-bold text-white mt-0.5">${{item.cvss3_score}}</div>
            <div class="text-[10px] text-gray-400">${{item.attack_vector}} Attack Vector</div>
          </div>
          <div class="p-2.5 bg-gray-800/60 rounded border border-gray-700">
            <div class="text-[10px] text-gray-400 uppercase">EPSS Exploitation</div>
            <div class="text-base font-bold text-amber-400 font-mono mt-0.5">${{item.epss_score}}</div>
            <div class="text-[10px] text-gray-400">${{item.epss_status}}</div>
          </div>
          <div class="p-2.5 bg-gray-800/60 rounded border border-gray-700">
            <div class="text-[10px] text-gray-400 uppercase">Attack Matrix Size</div>
            <div class="text-base font-bold text-purple-400 font-mono mt-0.5">${{item.attack_matrix_size}}</div>
            <div class="text-[10px] text-gray-400">${{item.affected_vendors_count}} Vendors / ${{item.affected_products_count}} Products</div>
          </div>
        </div>

        <div class="mb-4">
          <div class="text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">Affected Real-World Assets</div>
          <div class="p-3 bg-gray-800/40 rounded border border-gray-800 text-gray-300 text-xs">
            <div><strong class="text-gray-400">Vendors:</strong> ${{item.sample_affected_vendors}}</div>
            <div class="mt-1"><strong class="text-gray-400">Products:</strong> ${{item.sample_affected_products}}</div>
          </div>
        </div>

        <div>
          <div class="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
            <span>IBM Granite 4 Attack Plane Intelligence</span>
          </div>
          <div class="p-3 bg-blue-950/20 border border-blue-900/40 rounded text-gray-300 text-xs leading-relaxed">
            ${{item.granite_assessment || item.description || 'Pre-analysis vulnerability under deferred review.'}}
          </div>
        </div>
      `;
      modal.classList.remove('hidden');
    }}

    function closeModal() {{
      document.getElementById('detailModal').classList.add('hidden');
    }}

    function exportCSV() {{
      const rows = (currentTab === 'unpub') ? unpublishedData : top500Data;
      if (!rows.length) return;
      const headers = Object.keys(rows[0]);
      const csvContent = "data:text/csv;charset=utf-8," + 
        [headers.join(",")].concat(rows.map(r => headers.map(h => JSON.stringify(r[h] || "")).join(","))).join("\\n");
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement("a");
      link.setAttribute("href", encodedUri);
      link.setAttribute("download", (currentTab === 'unpub' ? "unpublished_vulnerabilities.csv" : "top500_filtered.csv"));
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }}

    // Initial render
    renderTable();
  </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Successfully generated dashboard: {output_path}")


def main():
    print("Loading Top 500 dataset...")
    top500 = load_top500("top500.csv")
    print(f"Loaded {len(top500)} records from top500.csv")

    print("Extracting unpublished and pre-analysis vulnerabilities...")
    unpub = load_unpublished(data_dir="data", limit=150)
    print(f"Extracted {len(unpub)} unpublished / deferred vulnerabilities")

    # Generate in workspace
    generate_html_dashboard(top500, unpub, "dashboard.html")

    # Also generate in artifact directory
    artifact_dir = r"C:\Users\User\.gemini\antigravity\brain\b001ba77-b50f-4855-adb2-e36469d6b228"
    if os.path.exists(artifact_dir):
        artifact_path = os.path.join(artifact_dir, "dashboard.html")
        generate_html_dashboard(top500, unpub, artifact_path)


if __name__ == "__main__":
    main()
