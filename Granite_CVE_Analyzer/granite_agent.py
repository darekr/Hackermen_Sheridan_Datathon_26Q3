"""
Granite Security Scoring Agent
Leverages IBM Granite foundation models (granite4:3b / granite-code:3b) to score:
1. CVSS Severity & Exploitability
2. EPSS Probability & Version-Aware Weighting (EPSS v4 policy)
3. Attack Matrix Size & Real-World Attack Plane (derived from affected_products.csv)

Enforces:
- If EPSS score is 0, this means no information is available in scoreboard.
- Any EPSS recorded prior to the release of EPSS v4 in early 2025 is weighted less (0.6x) than EPSS v4 (1.0x).
"""

import os
import sys
import csv
import json
import math
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from csv_compare_agent.epss_weighting import EPSSWeightingConfig, weighted_epss


class GraniteScoringAgent:
    """
    Agent for scoring CVEs across CVSS, EPSS, and Attack Matrix Size,
    and evaluating the real-world attack plane using IBM Granite.
    """

    def __init__(
        self,
        model_name: str = "granite4:3b",
        ollama_url: str = "http://localhost:11434",
        data_dir: str = "data",
        v4_release_month: str = "2025-03",
        pre_v4_weight: float = 0.6
    ):
        self.model_name = model_name
        self.ollama_url = ollama_url.rstrip("/")
        self.data_dir = os.path.abspath(data_dir)
        self.epss_config = EPSSWeightingConfig(
            v4_release_month=v4_release_month,
            pre_v4_weight=pre_v4_weight,
            v4_weight=1.0
        )
        self.vuln_path = os.path.join(self.data_dir, "vulnerabilities.csv")
        self.scoreboard_path = os.path.join(self.data_dir, "scoreboard_2026.csv")
        self.products_path = os.path.join(self.data_dir, "affected_products.csv")
        self.cwe_path = os.path.join(self.data_dir, "weakness_types.csv")
        self.kev_path = os.path.join(self.data_dir, "known_exploited.csv")

        # In-memory caches for fast lookup
        self._cwe_map: Optional[Dict[str, Dict[str, str]]] = None
        self._kev_set: Optional[set] = None

    def _load_cwe_map(self) -> Dict[str, Dict[str, str]]:
        if self._cwe_map is not None:
            return self._cwe_map
        m = {}
        if os.path.exists(self.cwe_path):
            with open(self.cwe_path, "r", encoding="utf-8", errors="replace") as f:
                for row in csv.DictReader(f):
                    cwe = row.get("cwe_id", "").strip().upper()
                    if cwe:
                        m[cwe] = {
                            "name": row.get("name", "Unknown Weakness"),
                            "description": row.get("description", "")
                        }
        self._cwe_map = m
        return m

    def _load_kev_set(self) -> set:
        if self._kev_set is not None:
            return self._kev_set
        s = set()
        if os.path.exists(self.kev_path):
            with open(self.kev_path, "r", encoding="utf-8", errors="replace") as f:
                for row in csv.DictReader(f):
                    cve = row.get("cve_id", "").strip().upper()
                    if cve:
                        s.add(cve)
        self._kev_set = s
        return s

    def query_granite(self, prompt: str, timeout: int = 45) -> str:
        """Sends a prompt to the local IBM Granite model via Ollama."""
        endpoint = f"{self.ollama_url}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "top_p": 0.9
            }
        }
        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "").strip()
        except Exception as e:
            return f"[Granite model unavailable: {e}]"

    def compute_attack_matrix_size(
        self,
        vendors_count: int,
        products_count: int,
        configurations_count: int,
        attack_vector: str
    ) -> float:
        """
        Calculates the real-world Attack Matrix Size (AMS).
        Scales with the logarithmic diversity of vendors, products, and configurations,
        modulated by the network exposure vector.
        """
        vec = (attack_vector or "NETWORK").upper()
        if "NETWORK" in vec:
            vec_mult = 1.0
        elif "ADJACENT" in vec:
            vec_mult = 0.8
        elif "LOCAL" in vec:
            vec_mult = 0.5
        else:
            vec_mult = 0.3

        base_matrix = (
            math.log1p(vendors_count) * 2.5 +
            math.log1p(products_count) * 2.5 +
            math.log1p(configurations_count) * 1.0
        )
        return round(base_matrix * vec_mult, 2)

    def determine_attack_plane_scope(
        self,
        vendors: List[str],
        products: List[str],
        attack_vector: str
    ) -> str:
        """Classifies the primary real-world attack plane category."""
        vec = (attack_vector or "NETWORK").upper()
        all_text = " ".join(vendors + products).lower()

        if any(w in all_text for w in ["router", "switch", "cisco", "fortinet", "paloalto", "juniper", "vpn", "gateway"]):
            plane = "Enterprise Edge & Network Infrastructure"
        elif any(w in all_text for w in ["linux", "kernel", "windows", "bsd", "solaris", "operating_system"]):
            plane = "Core Operating System & Kernel"
        elif any(w in all_text for w in ["apache", "nginx", "httpd", "php", "django", "node", "web", "wordpress", "iis"]):
            plane = "Web Servers & Cloud Applications"
        elif any(w in all_text for w in ["database", "mysql", "postgres", "oracle", "mongodb", "sqlite"]):
            plane = "Database & Critical Storage Systems"
        elif any(w in all_text for w in ["chrome", "firefox", "safari", "edge", "browser"]):
            plane = "Client Browser & Web Endpoints"
        else:
            plane = "Distributed Software Ecosystem"

        if "NETWORK" in vec:
            return f"{plane} (Remotely Exposed)"
        return f"{plane} (Locally Constrained)"

    def assess_attack_plane_with_granite(
        self,
        cve_id: str,
        cwe_info: str,
        cvss_score: float,
        epss_score: float,
        epss_status: str,
        attack_matrix_size: float,
        vendors: List[str],
        products: List[str],
        attack_vector: str
    ) -> str:
        """Prompts IBM Granite to assess real-world attack plane impact."""
        prompt = f"""<|start_of_role|>system<|end_of_role|>
You are Granite CVE Security Agent. Provide a concise 2-sentence real-world attack plane evaluation.
Focus on real-world exploitability, target environment exposure, and defense urgency.

<|start_of_role|>user<|end_of_role|>
Assess the real-world attack plane for:
- Vulnerability: {cve_id}
- Weakness: {cwe_info}
- CVSS: {cvss_score} (Attack Vector: {attack_vector})
- EPSS: {epss_score} ({epss_status})
- Attack Matrix Size: {attack_matrix_size}
- Affected Assets: Vendors [{', '.join(vendors[:3])}], Products [{', '.join(products[:4])}]
<|start_of_role|>assistant<|end_of_role|>
"""
        return self.query_granite(prompt)

    def generate_top500(
        self,
        output_file: str = "top500.csv",
        llm_sample_count: int = 15
    ) -> str:
        """
        Processes scoreboard_2026.csv, correlates with vulnerabilities.csv
        and affected_products.csv, scores all CVEs, and exports top500.csv.
        """
        print(f"[*] Starting Granite Top 500 generation...")
        print(f"[*] Model: {self.model_name} | Data directory: {self.data_dir}")

        cwe_map = self._load_cwe_map()
        kev_set = self._load_kev_set()

        # Step 1: Load scoreboard_2026.csv
        scoreboard = {}
        with open(self.scoreboard_path, "r", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                cve = row.get("cve_id", "").strip().upper()
                if not cve:
                    continue
                raw_epss_str = row.get("epss", "").strip()
                try:
                    raw_epss = float(raw_epss_str) if raw_epss_str else 0.0
                except ValueError:
                    raw_epss = 0.0

                month = row.get("snapshot_month", "2026-03").strip()
                pub = row.get("published", "").strip()

                # Rule: anywhere the publish date is after the snapshot_month value, assume the snapshot data instead
                if pub and month and (pub > month or pub[:7] > month):
                    effective_date = month
                    assumed_snapshot_data = True
                else:
                    effective_date = pub or month
                    assumed_snapshot_data = False

                scoreboard[cve] = {
                    "raw_epss": raw_epss,
                    "month": month,
                    "published": pub,
                    "effective_date": effective_date,
                    "assumed_snapshot_data": assumed_snapshot_data,
                    "exploitdb": int(row.get("exploitdb") or 0),
                    "metasploit": int(row.get("metasploit") or 0),
                    "poc_github": int(row.get("poc_github") or 0)
                }

        print(f"[+] Loaded {len(scoreboard)} target CVEs from scoreboard_2026.csv")

        # Step 2: Stream affected_products.csv
        product_stats: Dict[str, Dict[str, Any]] = {}
        if os.path.exists(self.products_path):
            with open(self.products_path, "r", encoding="utf-8", errors="replace") as f:
                for row in csv.DictReader(f):
                    cve = row.get("cve_id", "").strip().upper()
                    if cve in scoreboard:
                        if cve not in product_stats:
                            product_stats[cve] = {
                                "vendors": set(),
                                "products": set(),
                                "configs_count": 0
                            }
                        product_stats[cve]["configs_count"] += 1
                        if row.get("vendor"):
                            product_stats[cve]["vendors"].add(row["vendor"].strip())
                        if row.get("product"):
                            product_stats[cve]["products"].add(row["product"].strip())

        print(f"[+] Compiled affected product footprints for {len(product_stats)} scoreboard CVEs")

        # Step 3: Stream vulnerabilities.csv and score
        scored_candidates = []
        with open(self.vuln_path, "r", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                cve = row.get("cve_id", "").strip().upper()
                if cve not in scoreboard:
                    continue

                sc = scoreboard[cve]
                raw_epss = sc["raw_epss"]

                # Rule: If EPSS score is 0, this means no information is available in scoreboard
                if raw_epss == 0.0:
                    epss_status = "No information available in scoreboard"
                    w_epss = 0.0
                else:
                    epss_status = "Active in Scoreboard"
                    # Version-aware weighting (2026 is v4 = weight 1.0; if pre-2025 month = 0.6)
                    w_epss = self.epss_config.weight_score(raw_epss, sc["month"])

                # CVSS Base Score
                cvss_str = row.get("cvss3_score") or row.get("cvss2_score") or "0.0"
                try:
                    cvss = float(cvss_str)
                except ValueError:
                    cvss = 0.0

                severity = row.get("cvss3_severity") or ("HIGH" if cvss >= 7.0 else "MEDIUM")
                attack_vec = row.get("attack_vector") or "NETWORK"

                # Attack Matrix Size
                p_info = product_stats.get(cve, {"vendors": set(), "products": set(), "configs_count": 0})
                v_cnt = len(p_info["vendors"])
                p_cnt = len(p_info["products"])
                cfg_cnt = p_info["configs_count"]
                ams = self.compute_attack_matrix_size(v_cnt, p_cnt, cfg_cnt, attack_vec)

                # Composite Threat Score (0.0 to 100.0)
                # CVSS (max 35 pts)
                score_cvss = (cvss / 10.0) * 35.0
                # EPSS weighted (max 35 pts)
                score_epss = w_epss * 35.0
                # Attack Matrix Size (max 20 pts)
                score_ams = min(20.0, ams * 2.2)
                # Active Weaponization & KEV (max 10 pts)
                score_weap = 0.0
                if cve in kev_set:
                    score_weap += 5.0
                if sc["metasploit"]:
                    score_weap += 3.0
                if sc["exploitdb"]:
                    score_weap += 2.0

                composite = round(min(100.0, score_cvss + score_epss + score_ams + score_weap), 2)

                # Weakness information
                raw_cwe = row.get("cwe_ids", "").strip() or "NVD-CWE-noinfo"
                primary_cwe = raw_cwe.split(";")[0].strip().upper()
                cwe_details = cwe_map.get(primary_cwe, {})
                cwe_name = cwe_details.get("name", "Vulnerability Weakness")

                vendors_list = sorted(list(p_info["vendors"]))
                products_list = sorted(list(p_info["products"]))
                attack_plane = self.determine_attack_plane_scope(vendors_list, products_list, attack_vec)

                scored_candidates.append({
                    "cve_id": cve,
                    "composite_score": composite,
                    "cvss3_score": cvss,
                    "cvss3_severity": severity,
                    "attack_vector": attack_vec,
                    "epss_score": raw_epss,
                    "raw_epss": raw_epss,
                    "epss_status": epss_status,
                    "epss_weighted": w_epss,
                    "weighted_epss": w_epss,
                    "attack_matrix_size": ams,
                    "cwe_id": raw_cwe,
                    "cwe_name": cwe_name,
                    "affected_vendors_count": v_cnt,
                    "affected_products_count": p_cnt,
                    "sample_affected_vendors": "; ".join(vendors_list[:5]) if vendors_list else "Not Specified",
                    "sample_affected_products": "; ".join(products_list[:6]) if products_list else "Not Specified",
                    "attack_plane_scope": attack_plane,
                    "published_date": sc.get("published", ""),
                    "snapshot_month": sc.get("month", ""),
                    "effective_date": sc.get("effective_date", ""),
                    "assumed_snapshot_data": sc.get("assumed_snapshot_data", False),
                    "description": row.get("description", "")[:200]
                })

        # Sort descending by composite score
        scored_candidates.sort(key=lambda x: x["composite_score"], reverse=True)
        total_cves = len(scored_candidates)
        print(f"[+] Ranked all {total_cves} candidates across the dataset. Top composite score: {scored_candidates[0]['composite_score']}")

        # Step 4: Use IBM Granite to generate deep attack plane evaluations for top samples
        # and assign ranks & syntheses for all CVEs
        print(f"[*] Querying IBM Granite ({self.model_name}) for deep attack plane analysis on top candidates...")
        for i, item in enumerate(scored_candidates):
            item["rank"] = i + 1
            if i < llm_sample_count:
                print(f"    -> Evaluating Rank {i+1} [{item['cve_id']}] via Granite 4...")
                assessment = self.assess_attack_plane_with_granite(
                    cve_id=item["cve_id"],
                    cwe_info=f"{item['cwe_id']} ({item['cwe_name']})",
                    cvss_score=item["cvss3_score"],
                    epss_score=item["raw_epss"],
                    epss_status=item["epss_status"],
                    attack_matrix_size=item["attack_matrix_size"],
                    vendors=item["sample_affected_vendors"].split("; "),
                    products=item["sample_affected_products"].split("; "),
                    attack_vector=item["attack_vector"]
                )
                item["granite_attack_plane_assessment"] = assessment
            else:
                # Deterministic synthesis for subsequent ranks across the entire dataset
                item["granite_attack_plane_assessment"] = (
                    f"Real-world attack plane spans {item['attack_plane_scope']} across "
                    f"{item['affected_products_count']} products ({item['sample_affected_vendors']}). "
                    f"Threat severity driven by CVSS {item['cvss3_score']} with {item['epss_status']} (EPSS: {item['raw_epss']})."
                )

        # Step 5: Write all_cves_assessed.csv (All CVEs) and top500.csv (Top 500)
        fieldnames = [
            "rank",
            "cve_id",
            "composite_score",
            "cvss3_score",
            "cvss3_severity",
            "attack_vector",
            "epss_score",
            "epss_status",
            "epss_weighted",
            "attack_matrix_size",
            "cwe_id",
            "cwe_name",
            "affected_vendors_count",
            "affected_products_count",
            "sample_affected_vendors",
            "sample_affected_products",
            "attack_plane_scope",
            "published_date",
            "snapshot_month",
            "effective_date",
            "assumed_snapshot_data",
            "granite_attack_plane_assessment"
        ]

        # Write ALL assessed CVEs
        all_path = os.path.abspath(output_file)
        with open(all_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in scored_candidates:
                writer.writerow(row)
        print(f"[+] Successfully generated ALL assessed CVEs: {all_path} ({total_cves} records)")

        # Write top500.csv slice
        top500_path = os.path.abspath("top500.csv")
        with open(top500_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in scored_candidates[:500]:
                writer.writerow(row)
        print(f"[+] Successfully updated top 500 slice: {top500_path} (500 records)")

        return all_path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Granite Security Scoring Agent - Full Dataset Vulnerability Assessment")
    parser.add_argument("--model", default="granite4:3b", choices=["granite4:3b", "granite-code:3b"], help="IBM Granite model")
    parser.add_argument("--assess-all", action="store_true", default=True, help="Assess all CVEs across the dataset (default: True)")
    parser.add_argument("--output", default="all_cves_assessed.csv", help="Output path for assessed CVEs (default: all_cves_assessed.csv)")
    parser.add_argument("--cve", help="Score a specific CVE")
    args = parser.parse_args()

    agent = GraniteScoringAgent(model_name=args.model)

    if args.cve:
        print(f"Scoring {args.cve}...")
        res = agent.lookup_cve(args.cve)
        print(json.dumps(res, indent=2))
    else:
        agent.generate_top500(output_file=args.output)


if __name__ == "__main__":
    main()

