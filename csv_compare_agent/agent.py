"""
CSVCompareAgent - The multi-CSV analytical comparison agent.
Provides automated schema diffing, record-level auditing, statistical shift detection,
cross-dataset SQL querying, and exportable markdown reports.
"""

import os
import re
import json
import sqlite3
from typing import List, Dict, Any, Optional, Union
from .profiler import DatasetWrapper, MultiCSVProfiler, HAS_PANDAS, HAS_DUCKDB

if HAS_PANDAS:
    import pandas as pd
if HAS_DUCKDB:
    import duckdb


class CSVCompareAgent:
    """
    An intelligent comparison agent for multiple CSV files.

    Example usage:
    --------------
    agent = CSVCompareAgent(["train_v1.csv", "train_v2.csv"])
    print(agent.summary())
    report = agent.compare_all()
    agent.generate_markdown_report("audit_report.md")
    """

    def __init__(self, file_paths: Optional[List[str]] = None, aliases: Optional[List[str]] = None):
        self.datasets: Dict[str, DatasetWrapper] = {}
        self._sqlite_conn: Optional[sqlite3.Connection] = None
        self._duckdb_conn = None

        if file_paths:
            for i, path in enumerate(file_paths):
                alias = aliases[i] if aliases and i < len(aliases) else None
                self.add_csv(path, alias=alias)

    def _sanitize_table_name(self, name: str) -> str:
        """Create a safe SQL identifier for table names."""
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        if clean[0].isdigit():
            clean = "t_" + clean
        return clean.lower()

    def add_csv(self, file_path: str, alias: Optional[str] = None) -> str:
        """Loads a new CSV file into the agent."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"CSV file not found: {file_path}")

        base_name = os.path.splitext(os.path.basename(file_path))[0]
        name = alias if alias else base_name

        # Prevent duplicate alias collisions
        idx = 2
        orig_name = name
        while name in self.datasets:
            name = f"{orig_name}_{idx}"
            idx += 1

        wrapper = DatasetWrapper(name=name, file_path=file_path)
        self.datasets[name] = wrapper
        self._reset_sql_connections()
        return name

    def _reset_sql_connections(self):
        if self._sqlite_conn:
            try:
                self._sqlite_conn.close()
            except Exception:
                pass
            self._sqlite_conn = None
        self._duckdb_conn = None

    @property
    def profiler(self) -> MultiCSVProfiler:
        return MultiCSVProfiler(self.datasets)

    def summary(self) -> Dict[str, Any]:
        """Provides an executive summary of all registered datasets."""
        info = {}
        for name, ds in self.datasets.items():
            info[name] = {
                "file_path": ds.file_path,
                "file_size_kb": round(ds.file_size_bytes / 1024, 2),
                "row_count": ds.row_count,
                "column_count": len(ds.headers),
                "columns": ds.headers,
                "candidate_keys": ds.get_candidate_keys(),
                "null_columns": {col: count for col, count in ds.null_counts.items() if count > 0}
            }
        return info

    def compare_schemas(self) -> Dict[str, Any]:
        """Analyzes schema consistency, common columns, unique columns, and type differences."""
        if len(self.datasets) < 2:
            return {"warning": "At least two CSV files are required for comparison."}
        return self.profiler.schema_comparison()

    def diff_records(
        self,
        dataset_a: Optional[str] = None,
        dataset_b: Optional[str] = None,
        key_column: Optional[str] = None,
        max_samples: int = 15
    ) -> Dict[str, Any]:
        """
        Calculates record differences between two datasets:
        Added records, deleted records, and cell-level modifications.
        """
        names = list(self.datasets.keys())
        if len(names) < 2:
            raise ValueError("Need at least 2 CSV files to perform record diff.")

        name_a = dataset_a or names[0]
        name_b = dataset_b or names[1]

        return self.profiler.diff_records(name_a, name_b, key_column=key_column, max_sample_diffs=max_samples)

    def compare_statistics(
        self,
        dataset_a: Optional[str] = None,
        dataset_b: Optional[str] = None
    ) -> Dict[str, Any]:
        """Computes statistical drift and categorical shifts across shared columns."""
        names = list(self.datasets.keys())
        if len(names) < 2:
            raise ValueError("Need at least 2 CSV files to compare statistics.")

        name_a = dataset_a or names[0]
        name_b = dataset_b or names[1]

        return self.profiler.statistical_comparison(name_a, name_b)

    def compare_all(self, dataset_a: Optional[str] = None, dataset_b: Optional[str] = None) -> Dict[str, Any]:
        """Runs the entire comparison suite across all loaded CSV files."""
        names = list(self.datasets.keys())
        if len(names) < 2:
            return {"summary": self.summary()}

        a = dataset_a or names[0]
        b = dataset_b or names[1]

        return {
            "summary": self.summary(),
            "schema_comparison": self.compare_schemas(),
            "record_diff": self.diff_records(a, b),
            "statistical_comparison": self.compare_statistics(a, b)
        }

    def _init_sql(self):
        """Prepares in-memory SQLite and DuckDB query engines."""
        if HAS_DUCKDB and self._duckdb_conn is None:
            self._duckdb_conn = duckdb.connect(database=":memory:")
            for name, ds in self.datasets.items():
                tbl = self._sanitize_table_name(name)
                if ds.df is not None:
                    self._duckdb_conn.register(tbl, ds.df)
                else:
                    self._duckdb_conn.execute(f"CREATE TABLE {tbl} AS SELECT * FROM read_csv_auto('{ds.file_path}')")

        if self._sqlite_conn is None:
            self._sqlite_conn = sqlite3.connect(":memory:")
            for name, ds in self.datasets.items():
                tbl = self._sanitize_table_name(name)
                if HAS_PANDAS and ds.df is not None:
                    ds.df.to_sql(tbl, self._sqlite_conn, index=False, if_exists="replace")

    def sql(self, query: str) -> List[Dict[str, Any]]:
        """
        Executes a SQL query across the loaded datasets.
        Tables are named after sanitized dataset aliases (e.g. `v1`, `v2`, or `file_name`).
        """
        self._init_sql()

        if HAS_DUCKDB and self._duckdb_conn:
            try:
                res = self._duckdb_conn.execute(query).df()
                return res.to_dict(orient="records")
            except Exception as e:
                # If duckdb fails or is unavailable, fallback to sqlite
                pass

        if self._sqlite_conn:
            cursor = self._sqlite_conn.cursor()
            cursor.execute(query)
            cols = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            return [dict(zip(cols, row)) for row in rows]

        raise RuntimeError("No SQL engine available. Please install pandas or duckdb.")

    def ask(self, question: str) -> str:
        """
        Natural language reasoning agent over the datasets.
        Synthesizes schemas, diffs, and statistics to answer user inquiries.
        """
        q = question.lower()
        names = list(self.datasets.keys())
        if len(names) < 2:
            return f"I have loaded {len(names)} dataset: {list(self.datasets.keys())}. Please load another to compare."

        a, b = names[0], names[1]

        if "schema" in q or "column" in q or "structure" in q:
            schema = self.compare_schemas()
            common = schema.get("common_columns", [])
            unique = schema.get("unique_columns_by_file", {})
            conflicts = schema.get("type_conflicts", [])

            lines = [f"**Schema Comparison between `{a}` and `{b}`:**"]
            lines.append(f"- Shared Columns ({len(common)}): {', '.join(common)}")
            for name, cols in unique.items():
                lines.append(f"- Unique to `{name}` ({len(cols)}): {', '.join(cols) if cols else 'None'}")
            if conflicts:
                lines.append(f"- Type Conflicts: {conflicts}")
            return "\n".join(lines)

        if "diff" in q or "record" in q or "change" in q or "row" in q:
            diff = self.diff_records(a, b)
            lines = [
                f"**Record-level Diff (`{a}` vs `{b}`) using Key `{diff.get('key_column')}`:**",
                f"- Added in `{b}`: **{diff.get('added_count')}** rows",
                f"- Removed from `{a}`: **{diff.get('removed_count')}** rows",
                f"- Modified rows: **{diff.get('modified_count')}**",
                f"- Unchanged rows: **{diff.get('unchanged_count')}**"
            ]
            sample_mod = diff.get("sample_modified_records", [])
            if sample_mod:
                lines.append("\n**Sample Modifications:**")
                for item in sample_mod[:3]:
                    lines.append(f"  - Key `{item['key']}`: {item['changes']}")
            return "\n".join(lines)

        if "stat" in q or "drift" in q or "mean" in q or "average" in q:
            stats = self.compare_statistics(a, b)
            lines = [f"**Statistical Comparison (`{a}` vs `{b}`):**"]
            for col, data in list(stats.items())[:5]:
                if data["type"] == "numeric":
                    lines.append(f"- `{col}`: Mean in {a}={data['mean_a']}, Mean in {b}={data['mean_b']} (Delta: {data['mean_delta']})")
                else:
                    lines.append(f"- `{col}` (Categorical): {data['unique_count_a']} unique in {a} -> {data['unique_count_b']} unique in {b}")
            return "\n".join(lines)

        # General summary answer
        summary = self.summary()
        res = [f"**Overview of Loaded Datasets:**"]
        for name, meta in summary.items():
            res.append(f"- **{name}**: {meta['row_count']} rows, {meta['column_count']} columns ({meta['file_size_kb']} KB)")
        return "\n".join(res)

    def generate_markdown_report(self, output_path: Optional[str] = None) -> str:
        """
        Generates a comprehensive Markdown comparison report with formatted tables.
        """
        names = list(self.datasets.keys())
        if len(names) < 2:
            content = "# Multi-CSV Comparison Report\n\n*Error: Need at least 2 datasets to generate comparison report.*"
            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(content)
            return content

        a, b = names[0], names[1]
        schema = self.compare_schemas()
        diff = self.diff_records(a, b)
        stats = self.compare_statistics(a, b)

        lines = [
            f"# Multi-CSV Dataset Audit & Comparison Report",
            f"\n**Compared Datasets:** `{a}` vs `{b}`",
            f"\n## 1. Executive Summary\n",
            f"| Metric | `{a}` | `{b}` | Delta |",
            f"| :--- | :--- | :--- | :--- |",
            f"| Total Rows | {self.datasets[a].row_count} | {self.datasets[b].row_count} | {self.datasets[b].row_count - self.datasets[a].row_count:+d} |",
            f"| Total Columns | {len(self.datasets[a].headers)} | {len(self.datasets[b].headers)} | {len(self.datasets[b].headers) - len(self.datasets[a].headers):+d} |",
            f"| File Size (KB) | {round(self.datasets[a].file_size_bytes/1024, 1)} | {round(self.datasets[b].file_size_bytes/1024, 1)} | - |",
            f"\n## 2. Schema Analysis\n",
            f"- **Shared Columns ({len(schema['common_columns'])}):** `{', '.join(schema['common_columns'])}`",
        ]

        unique_a = schema["unique_columns_by_file"].get(a, [])
        unique_b = schema["unique_columns_by_file"].get(b, [])
        if unique_a:
            lines.append(f"- **Columns unique to `{a}`:** `{', '.join(unique_a)}`")
        if unique_b:
            lines.append(f"- **Columns unique to `{b}`:** `{', '.join(unique_b)}`")

        if schema["type_conflicts"]:
            lines.append(f"\n> [!WARNING]\n> Data type conflicts detected in: {schema['type_conflicts']}")
        else:
            lines.append(f"\n> [!NOTE]\n> Column data types are consistent across all shared fields.")

        lines.extend([
            f"\n## 3. Record-Level Auditing (Key: `{diff.get('key_column')}`)\n",
            f"| Change Type | Record Count | Percentage of Shared Keys |",
            f"| :--- | :--- | :--- |",
            f"| **Added in `{b}`** | {diff.get('added_count')} | - |",
            f"| **Removed from `{a}`** | {diff.get('removed_count')} | - |",
            f"| **Modified Records** | {diff.get('modified_count')} | {round((diff.get('modified_count', 0) / max(1, diff.get('shared_keys_count', 1))) * 100, 1)}% |",
            f"| **Unchanged Records** | {diff.get('unchanged_count')} | {round((diff.get('unchanged_count', 0) / max(1, diff.get('shared_keys_count', 1))) * 100, 1)}% |",
        ])

        col_changes = diff.get("column_change_counts", {})
        if col_changes:
            lines.append(f"\n### Frequency of Value Changes by Field\n")
            lines.append(f"| Column | Changed Records |")
            lines.append(f"| :--- | :--- |")
            for col, cnt in sorted(col_changes.items(), key=lambda x: x[1], reverse=True):
                if cnt > 0:
                    lines.append(f"| `{col}` | {cnt} |")

        if stats:
            lines.append(f"\n## 4. Statistical Shift & Data Drift\n")
            lines.append(f"| Column | Type | Mean `{a}` | Mean `{b}` | Delta | Null % `{a}` -> `{b}` |")
            lines.append(f"| :--- | :--- | :--- | :--- | :--- | :--- |")
            for col, item in stats.items():
                if item["type"] == "numeric":
                    lines.append(f"| `{col}` | Numeric | {item['mean_a']} | {item['mean_b']} | {item['mean_delta']:+0.2f} | {item['null_pct_a']}% -> {item['null_pct_b']}% |")
                else:
                    lines.append(f"| `{col}` | Categorical | {item['unique_count_a']} uniques | {item['unique_count_b']} uniques | New: {item['new_categories_in_b']} | {item['null_pct_a']}% -> {item['null_pct_b']}% |")

        report_md = "\n".join(lines)

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report_md)

        return report_md

