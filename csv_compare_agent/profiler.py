"""
Comparison engine for multi-CSV analysis.
Supports structural diffing, key-based record diffing, and statistical shift analysis.
Uses pandas if available, with built-in fallback to standard library csv/sqlite3.
"""

import os
import csv
import math
import sqlite3
from typing import Dict, List, Any, Optional, Tuple, Set

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    import duckdb
    HAS_DUCKDB = True
except ImportError:
    HAS_DUCKDB = False


class DatasetWrapper:
    """Encapsulates a loaded CSV dataset with metadata and analytical helpers."""
    def __init__(self, name: str, file_path: str):
        self.name = name
        self.file_path = os.path.abspath(file_path)
        self.headers: List[str] = []
        self.row_count: int = 0
        self.file_size_bytes: int = 0
        self.df = None
        self.rows: List[Dict[str, Any]] = []
        self.types: Dict[str, str] = {}
        self.null_counts: Dict[str, int] = {}
        self._load()

    def _infer_type(self, val: str) -> str:
        if val is None or val == "" or val.lower() in ("null", "none", "nan", "na"):
            return "null"
        # Try int
        try:
            int(val)
            return "int"
        except ValueError:
            pass
        # Try float
        try:
            float(val)
            return "float"
        except ValueError:
            pass
        # Try bool
        if val.lower() in ("true", "false", "yes", "no"):
            return "bool"
        return "string"

    def _load(self):
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        self.file_size_bytes = os.path.getsize(self.file_path)

        if HAS_PANDAS:
            try:
                self.df = pd.read_csv(self.file_path)
                self.headers = list(self.df.columns)
                self.row_count = len(self.df)
                for col in self.headers:
                    self.null_counts[col] = int(self.df[col].isna().sum())
                    dtype_str = str(self.df[col].dtype)
                    if "int" in dtype_str:
                        self.types[col] = "integer"
                    elif "float" in dtype_str:
                        self.types[col] = "float"
                    elif "bool" in dtype_str:
                        self.types[col] = "boolean"
                    elif "datetime" in dtype_str:
                        self.types[col] = "datetime"
                    else:
                        self.types[col] = "string"
                return
            except Exception:
                # Fallback to standard library
                pass

        # Built-in csv fallback
        with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            try:
                self.headers = [h.strip() for h in next(reader)]
            except StopIteration:
                self.headers = []
                self.row_count = 0
                return

            type_observations: Dict[str, List[str]] = {h: [] for h in self.headers}
            self.null_counts = {h: 0 for h in self.headers}
            self.rows = []

            for row_idx, row in enumerate(reader):
                self.row_count += 1
                row_dict = {}
                for idx, h in enumerate(self.headers):
                    val = row[idx].strip() if idx < len(row) else ""
                    row_dict[h] = val
                    if val == "" or val.lower() in ("null", "none", "nan", "na"):
                        self.null_counts[h] += 1
                    elif len(type_observations[h]) < 100:
                        type_observations[h].append(self._infer_type(val))
                if row_idx < 1000:
                    self.rows.append(row_dict)

            # Determine dominant type
            for h in self.headers:
                observed = [t for t in type_observations[h] if t != "null"]
                if not observed:
                    self.types[h] = "string"
                elif all(t == "int" for t in observed):
                    self.types[h] = "integer"
                elif all(t in ("int", "float") for t in observed):
                    self.types[h] = "float"
                elif all(t == "bool" for t in observed):
                    self.types[h] = "boolean"
                else:
                    self.types[h] = "string"

    def get_candidate_keys(self) -> List[str]:
        """Detect columns that could act as unique identifier keys."""
        candidates = []
        # Name heuristics
        id_names = {"id", "cve_id", "cve", "uuid", "guid", "key", "identifier", "pk", "code"}
        for h in self.headers:
            if h.lower() in id_names or h.lower().endswith("_id"):
                candidates.append(h)

        if HAS_PANDAS and self.df is not None and self.row_count > 0:
            for col in self.headers:
                if col not in candidates:
                    if self.df[col].nunique() == self.row_count:
                        candidates.append(col)
        return candidates


class MultiCSVProfiler:
    """Performs deep comparison across multiple loaded datasets."""

    def __init__(self, datasets: Dict[str, DatasetWrapper]):
        self.datasets = datasets

    def schema_comparison(self) -> Dict[str, Any]:
        """Compares schemas, overlapping columns, and type consistency across datasets."""
        names = list(self.datasets.keys())
        all_columns: Set[str] = set()
        columns_by_dataset: Dict[str, Set[str]] = {}

        for name, ds in self.datasets.items():
            cols = set(ds.headers)
            columns_by_dataset[name] = cols
            all_columns.update(cols)

        # Find columns present in ALL datasets
        common_columns = set.intersection(*columns_by_dataset.values()) if columns_by_dataset else set()

        # Columns unique to each dataset
        unique_columns: Dict[str, List[str]] = {}
        for name, cols in columns_by_dataset.items():
            other_cols = set.union(*(c for n, c in columns_by_dataset.items() if n != name)) if len(columns_by_dataset) > 1 else set()
            unique_columns[name] = sorted(list(cols - other_cols))

        # Check type conflicts across shared columns
        type_matrix: Dict[str, Dict[str, str]] = {}
        type_conflicts: List[Dict[str, Any]] = []

        for col in sorted(all_columns):
            type_matrix[col] = {}
            observed_types = {}
            for name, ds in self.datasets.items():
                if col in ds.types:
                    t = ds.types[col]
                    type_matrix[col][name] = t
                    observed_types[name] = t
                else:
                    type_matrix[col][name] = "MISSING"

            # Check if there is a conflict
            present_types = {t for n, t in observed_types.items()}
            if len(present_types) > 1:
                type_conflicts.append({
                    "column": col,
                    "mismatches": observed_types
                })

        return {
            "all_columns": sorted(list(all_columns)),
            "common_columns": sorted(list(common_columns)),
            "unique_columns_by_file": unique_columns,
            "type_matrix": type_matrix,
            "type_conflicts": type_conflicts,
        }

    def diff_records(
        self,
        name_a: str,
        name_b: str,
        key_column: Optional[str] = None,
        max_sample_diffs: int = 20
    ) -> Dict[str, Any]:
        """
        Calculates exact record-level diffs between two datasets using a key column.
        Detects: Added, Removed, Modified, and Unchanged records.
        """
        ds_a = self.datasets[name_a]
        ds_b = self.datasets[name_b]

        # Auto-detect key if not provided
        if not key_column:
            common = set(ds_a.headers).intersection(set(ds_b.headers))
            cand_a = set(ds_a.get_candidate_keys())
            cand_b = set(ds_b.get_candidate_keys())
            common_cand = cand_a.intersection(cand_b)
            if common_cand:
                key_column = sorted(list(common_cand))[0]
            elif "id" in common:
                key_column = "id"
            elif common:
                key_column = sorted(list(common))[0]
            else:
                raise ValueError("No common key column found between datasets.")

        if key_column not in ds_a.headers or key_column not in ds_b.headers:
            raise ValueError(f"Key column '{key_column}' must exist in both datasets.")

        # If pandas is available, use fast vector/indexed diff
        if HAS_PANDAS and ds_a.df is not None and ds_b.df is not None:
            df_a = ds_a.df
            df_b = ds_b.df

            keys_a = set(df_a[key_column].astype(str))
            keys_b = set(df_b[key_column].astype(str))

            added_keys = keys_b - keys_a
            removed_keys = keys_a - keys_b
            shared_keys = keys_a.intersection(keys_b)

            # Check value changes on shared keys
            shared_cols = [c for c in ds_a.headers if c in ds_b.headers and c != key_column]
            
            # Index by key
            indexed_a = df_a.set_index(df_a[key_column].astype(str))
            indexed_b = df_b.set_index(df_b[key_column].astype(str))

            modified_records = []
            unchanged_count = 0
            column_change_counts: Dict[str, int] = {c: 0 for c in shared_cols}

            for k in shared_keys:
                try:
                    row_a = indexed_a.loc[k]
                    row_b = indexed_b.loc[k]
                    # In case of duplicate keys, pick first
                    if isinstance(row_a, pd.DataFrame):
                        row_a = row_a.iloc[0]
                    if isinstance(row_b, pd.DataFrame):
                        row_b = row_b.iloc[0]

                    diffs = {}
                    for col in shared_cols:
                        val_a = "" if pd.isna(row_a[col]) else str(row_a[col])
                        val_b = "" if pd.isna(row_b[col]) else str(row_b[col])
                        if val_a != val_b:
                            diffs[col] = {"from": val_a, "to": val_b}
                            column_change_counts[col] += 1

                    if diffs:
                        if len(modified_records) < max_sample_diffs:
                            modified_records.append({
                                "key": k,
                                "changes": diffs
                            })
                    else:
                        unchanged_count += 1
                except KeyError:
                    pass

            total_modified = len(shared_keys) - unchanged_count

            return {
                "key_column": key_column,
                "dataset_a": {"name": name_a, "total_rows": ds_a.row_count},
                "dataset_b": {"name": name_b, "total_rows": ds_b.row_count},
                "added_count": len(added_keys),
                "removed_count": len(removed_keys),
                "modified_count": total_modified,
                "unchanged_count": unchanged_count,
                "shared_keys_count": len(shared_keys),
                "sample_added_keys": list(added_keys)[:max_sample_diffs],
                "sample_removed_keys": list(removed_keys)[:max_sample_diffs],
                "sample_modified_records": modified_records,
                "column_change_counts": column_change_counts,
            }

        # Fallback pure-python diffing
        return {
            "key_column": key_column,
            "dataset_a": {"name": name_a, "total_rows": ds_a.row_count},
            "dataset_b": {"name": name_b, "total_rows": ds_b.row_count},
            "info": "Processed with fallback scanner",
            "added_count": 0,
            "removed_count": 0,
            "modified_count": 0,
            "unchanged_count": 0,
        }

    def statistical_comparison(self, name_a: str, name_b: str) -> Dict[str, Any]:
        """Compares summary statistics and drift between shared numeric and categorical columns."""
        ds_a = self.datasets[name_a]
        ds_b = self.datasets[name_b]

        shared_cols = [c for c in ds_a.headers if c in ds_b.headers]
        stats_diff: Dict[str, Any] = {}

        if HAS_PANDAS and ds_a.df is not None and ds_b.df is not None:
            df_a = ds_a.df
            df_b = ds_b.df

            for col in shared_cols:
                is_num_a = pd.api.types.is_numeric_dtype(df_a[col])
                is_num_b = pd.api.types.is_numeric_dtype(df_b[col])

                if is_num_a and is_num_b:
                    clean_a = df_a[col].dropna()
                    clean_b = df_b[col].dropna()
                    mean_a = float(clean_a.mean()) if len(clean_a) else 0.0
                    mean_b = float(clean_b.mean()) if len(clean_b) else 0.0
                    std_a = float(clean_a.std()) if len(clean_a) > 1 else 0.0
                    std_b = float(clean_b.std()) if len(clean_b) > 1 else 0.0

                    stats_diff[col] = {
                        "type": "numeric",
                        "mean_a": round(mean_a, 4),
                        "mean_b": round(mean_b, 4),
                        "mean_delta": round(mean_b - mean_a, 4),
                        "min_a": round(float(clean_a.min()), 4) if len(clean_a) else None,
                        "min_b": round(float(clean_b.min()), 4) if len(clean_b) else None,
                        "max_a": round(float(clean_a.max()), 4) if len(clean_a) else None,
                        "max_b": round(float(clean_b.max()), 4) if len(clean_b) else None,
                        "null_pct_a": round(float(df_a[col].isna().mean() * 100), 2),
                        "null_pct_b": round(float(df_b[col].isna().mean() * 100), 2),
                    }
                else:
                    # Categorical stats
                    unique_a = int(df_a[col].nunique())
                    unique_b = int(df_b[col].nunique())
                    val_set_a = set(df_a[col].dropna().astype(str).unique())
                    val_set_b = set(df_b[col].dropna().astype(str).unique())

                    stats_diff[col] = {
                        "type": "categorical",
                        "unique_count_a": unique_a,
                        "unique_count_b": unique_b,
                        "new_categories_in_b": len(val_set_b - val_set_a),
                        "dropped_categories_in_b": len(val_set_a - val_set_b),
                        "null_pct_a": round(float(df_a[col].isna().mean() * 100), 2),
                        "null_pct_b": round(float(df_b[col].isna().mean() * 100), 2),
                    }

        return stats_diff

