"""
Granite CVE Analyzer
A high-performance vulnerability analysis and risk intelligence system.
Integrates CVSS metrics, CISA KEV status, version-weighted EPSS (pre-v4 vs v4),
and multi-year exploit telemetry into actionable remediation briefs.
Designed for IBM Granite foundation models and automated datathon scoring.
"""

import os
import sys
import csv
import json
import argparse
from typing import Dict, Any, List, Optional

# Add parent directory to path so csv_compare_agent can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from csv_compare_agent.epss_weighting import EPSSWeightingConfig, weighted_epss


class GraniteCVEAnalyzer:
    """
    Core engine for correlating CVE metadata, exploit telemetry,
    affected software assets, and calculating weighted risk scores.
    """

    def __init__(
        self,
        data_dir: str = "data",
        v4_release_month: str = "2025-03",
        pre_v4_weight: float = 0.6
    ):
        self.data_dir = os.path.abspath(data_dir)
        self.epss_config = EPSSWeightingConfig(
            v4_release_month=v4_release_month,
            pre_v4_weight=pre_v4_weight,
            v4_weight=1.0
        )
        self.vuln_path = os.path.join(self.data_dir, "vulnerabilities.csv")
        self.kev_path = os.path.join(self.data_dir, "known_exploited.csv")
        self.signals_2024_path = os.path.join(self.data_dir, "exploit_signals_2024.csv")
        self.signals_2025_path = os.path.join(self.data_dir, "exploit_signals_2025.csv")
        self.scoreboard_2026_path = os.path.join(self.data_dir, "scoreboard_2026.csv")
        self.products_path = os.path.join(self.data_dir, "affected_products.csv")

        # In-memory indexes for fast lookups
        self._kev_cache: Optional[Dict[str, Dict[str, str]]] = None

    def _load_kev_cache(self) -> Dict[str, Dict[str, str]]:
        """Loads CISA Known Exploited Vulnerabilities into a fast lookup map."""
        if self._kev_cache is not None:
            return self._kev_cache

        cache = {}
        if os.path.exists(self.kev_path):
            with open(self.kev_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cve = row.get("cve_id", "").strip()
                    if cve:
                        cache[cve] = {
                            "vendor": row.get("vendor", ""),
                            "product": row.get("product", ""),
                            "name": row.get("name", ""),
                            "date_added": row.get("date_added", ""),
                            "ransomware_use": row.get("known_ransomware_use", "Unknown"),
                            "required_action": row.get("required_action", "")
                        }
        self._kev_cache = cache
        return cache

    def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Searches all datasets to build a complete profile for a specific CVE."""
        cve_id = cve_id.strip().upper()
        kev_map = self._load_kev_cache()

        profile: Dict[str, Any] = {
            "cve_id": cve_id,
            "in_cisa_kev": cve_id in kev_map,
            "kev_details": kev_map.get(cve_id),
            "vulnerability": None,
            "affected_products": [],
            "exploit_history": [],
            "risk_score": 0.0,
            "weighted_epss_current": 0.0
        }

        # 1. Lookup in vulnerabilities.csv
        if os.path.exists(self.vuln_path):
            with open(self.vuln_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("cve_id", "").strip().upper() == cve_id:
                        profile["vulnerability"] = {
                            "published": row.get("published"),
                            "description": row.get("description"),
                            "cvss3_score": float(row.get("cvss3_score") or 0.0),
                            "cvss3_severity": row.get("cvss3_severity"),
                            "attack_vector": row.get("attack_vector"),
                            "attack_complexity": row.get("attack_complexity"),
                            "cwe_ids": row.get("cwe_ids"),
                            "n_affected_cpes": row.get("n_affected_cpes")
                        }
                        break

        # 2. Lookup in affected_products.csv (sample first 10 products)
        if os.path.exists(self.products_path):
            with open(self.products_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("cve_id", "").strip().upper() == cve_id:
                        profile["affected_products"].append({
                            "vendor": row.get("vendor"),
                            "product": row.get("product"),
                            "version": row.get("version")
                        })
                        if len(profile["affected_products"]) >= 10:
                            break

        # 3. Lookup in exploit signals (2024, 2025, 2026)
        signal_files = [
            ("2024", self.signals_2024_path),
            ("2025", self.signals_2025_path),
            ("2026", self.scoreboard_2026_path)
        ]
        for year_label, file_path in signal_files:
            if not os.path.exists(file_path):
                continue
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                date_key = "month" if "month" in reader.fieldnames else "snapshot_month"
                for row in reader:
                    if row.get("cve_id", "").strip().upper() == cve_id:
                        month = row.get(date_key, "")
                        raw_epss = float(row.get("epss") or 0.0)
                        w_epss = self.epss_config.weight_score(raw_epss, month)
                        version = self.epss_config.get_version(month)

                        profile["exploit_history"].append({
                            "year": year_label,
                            "month": month,
                            "epss_raw": raw_epss,
                            "epss_version": version,
                            "epss_weight": self.epss_config.get_weight(month),
                            "epss_weighted": w_epss,
                            "in_kev": int(row.get("in_kev") or 0) if "in_kev" in row else None,
                            "exploitdb": int(row.get("exploitdb") or 0),
                            "metasploit": int(row.get("metasploit") or 0),
                            "nuclei": int(row.get("nuclei") or 0),
                            "poc_github": int(row.get("poc_github") or 0)
                        })

        # Calculate composite threat score
        profile["risk_score"] = self.calculate_composite_risk(profile)
        return profile

    def calculate_composite_risk(self, profile: Dict[str, Any]) -> float:
        """
        Computes an automated Composite Threat Index (0.0 to 100.0) combining:
        - Base CVSS score (0 to 10)
        - Version-weighted EPSS score (prioritizing EPSS v4)
        - Active exploitation telemetry (CISA KEV, Metasploit, ExploitDB, GitHub PoC)
        """
        cvss = 0.0
        if profile.get("vulnerability"):
            cvss = float(profile["vulnerability"].get("cvss3_score") or 0.0)

        # Get latest weighted EPSS and active exploit signals
        latest_weighted_epss = 0.0
        has_metasploit = False
        has_exploitdb = False
        has_poc = False

        if profile.get("exploit_history"):
            latest = profile["exploit_history"][-1]
            latest_weighted_epss = latest["epss_weighted"]
            has_metasploit = any(h.get("metasploit") == 1 for h in profile["exploit_history"])
            has_exploitdb = any(h.get("exploitdb") == 1 for h in profile["exploit_history"])
            has_poc = any(h.get("poc_github") == 1 for h in profile["exploit_history"])

        profile["weighted_epss_current"] = latest_weighted_epss

        # Weighted calculation
        # Base CVSS (max 40 pts)
        score = (cvss / 10.0) * 40.0
        # EPSS weighted (max 30 pts)
        score += min(30.0, latest_weighted_epss * 30.0)
        # CISA KEV (20 pts)
        if profile.get("in_cisa_kev"):
            score += 20.0
        # Weaponization signals (max 10 pts)
        if has_metasploit:
            score += 5.0
        if has_exploitdb:
            score += 3.0
        if has_poc:
            score += 2.0

        return round(min(100.0, score), 2)

    def generate_granite_prompt(self, profile: Dict[str, Any]) -> str:
        """
        Formats an optimal prompt for IBM Granite foundation models
        (e.g., granite-3.0-8b-instruct) for vulnerability remediation and triage.
        """
        cve = profile["cve_id"]
        vuln = profile.get("vulnerability") or {}
        kev = profile.get("kev_details") or {}
        products = profile.get("affected_products") or []
        history = profile.get("exploit_history") or []

        prompt = f"""<|start_of_role|>system<|end_of_role|>
You are Granite CVE Security Assistant, an expert cyber threat intelligence and vulnerability analysis AI model.
Analyze the provided CVE data, evaluate the EPSS v4 weighted threat score, and produce an executive risk assessment and remediation recommendation.

<|start_of_role|>user<|end_of_role|>
Please evaluate the following vulnerability profile:

**CVE Identifier:** {cve}
**Composite Threat Index:** {profile['risk_score']}/100.0
**CVSS 3.x Score:** {vuln.get('cvss3_score', 'N/A')} ({vuln.get('cvss3_severity', 'N/A')})
**Attack Vector:** {vuln.get('attack_vector', 'N/A')} | Complexity: {vuln.get('attack_complexity', 'N/A')}
**CWE Weakness:** {vuln.get('cwe_ids', 'N/A')}
**Description:** {vuln.get('description', 'No description available.')}

**CISA KEV Status:** {"CRITICAL: Listed in CISA KEV Catalog" if profile['in_cisa_kev'] else "Not currently listed in KEV"}
{f"- Ransomware Association: {kev.get('ransomware_use', 'Unknown')}" if profile['in_cisa_kev'] else ""}
{f"- Action Required: {kev.get('required_action', 'N/A')}" if profile['in_cisa_kev'] else ""}

**EPSS Telemetry (Version-Aware):**
- Current Weighted EPSS: {profile['weighted_epss_current']}
- Observation History: {len(history)} monthly snapshots analyzed.
- Exploit Signals: Metasploit={any(h.get('metasploit') == 1 for h in history)}, ExploitDB={any(h.get('exploitdb') == 1 for h in history)}, GitHub PoC={any(h.get('poc_github') == 1 for h in history)}

**Sample Affected Software Assets ({len(products)}):**
"""
        for p in products[:5]:
            prompt += f"- {p.get('vendor')} {p.get('product')} (version: {p.get('version')})\n"

        prompt += """
Please generate:
1. Executive Threat Summary & Urgency Level (CRITICAL / HIGH / MEDIUM / LOW).
2. Exploitability & Real-World Risk Analysis (referencing EPSS v4 trajectory and weaponization).
3. Immediate Mitigation & Patching Priority Steps.
<|start_of_role|>assistant<|end_of_role|>
"""
        return prompt


def main():
    parser = argparse.ArgumentParser(
        description="Granite CVE Analyzer - Vulnerability Intelligence & EPSS v4 Scoring"
    )
    parser.add_argument("cve", nargs="?", help="CVE identifier to inspect (e.g. CVE-2024-21413)")
    parser.add_argument("--v4-month", default="2025-03", help="EPSS v4 release cutoff month (default: 2025-03)")
    parser.add_argument("--pre-v4-weight", type=float, default=0.6, help="Weight discount for pre-v4 EPSS (default: 0.6)")
    parser.add_argument("--prompt", action="store_true", help="Output formatted IBM Granite prompt")
    parser.add_argument("--json", action="store_true", help="Output full profile as JSON")

    args = parser.parse_args()

    if not args.cve:
        print("Usage: python Granite_CVE_Analyzer/CVE_Analyzer.py <CVE-ID> [--prompt] [--json]")
        print("Example: python Granite_CVE_Analyzer/CVE_Analyzer.py CVE-2021-44228")
        return

    analyzer = GraniteCVEAnalyzer(
        v4_release_month=args.v4_month,
        pre_v4_weight=args.pre_v4_weight
    )

    print(f"Analyzing {args.cve.upper()}...")
    profile = analyzer.lookup_cve(args.cve)

    if not profile or not profile.get("vulnerability"):
        print(f"Warning: No record found for {args.cve} in local vulnerabilities database.")
        if profile and profile.get("exploit_history"):
            print(f"Found {len(profile['exploit_history'])} exploit history records.")

    if args.json:
        print(json.dumps(profile, indent=2))
        return

    if args.prompt:
        print("\n--- IBM Granite Model Prompt ---")
        print(analyzer.generate_granite_prompt(profile))
        return

    # Formatted Console Summary
    print("\n" + "=" * 60)
    print(f" CVE INTELLIGENCE PROFILE: {profile['cve_id']}")
    print("=" * 60)
    vuln = profile.get("vulnerability") or {}
    print(f"Composite Threat Index: {profile['risk_score']} / 100.0")
    print(f"CVSS 3.x Base Score:    {vuln.get('cvss3_score', 'N/A')} ({vuln.get('cvss3_severity', 'N/A')})")
    print(f"Attack Vector:          {vuln.get('attack_vector', 'N/A')}")
    print(f"In CISA KEV Catalog:    {'YES (ACTIVE IN THE WILD)' if profile['in_cisa_kev'] else 'No'}")
    print(f"Current Weighted EPSS:  {profile['weighted_epss_current']}")
    print(f"Exploit Snapshots:      {len(profile['exploit_history'])} recorded")

    if profile.get("exploit_history"):
        print("\nRecent Exploit Telemetry:")
        for h in profile["exploit_history"][-3:]:
            print(f"  [{h['month']}] Raw EPSS: {h['epss_raw']} -> Weighted: {h['epss_weighted']} (ver: {h['epss_version']}, ExploitDB: {h['exploitdb']}, Metasploit: {h['metasploit']})")

    print("\n[Tip] Run with --prompt to generate an IBM Granite foundation model prompt.")


if __name__ == "__main__":
    main()

