"""
Command-line interface for CSVCompareAgent.
Run via:
    python -m csv_compare_agent.cli data/exploit_signals_2024.csv data/exploit_signals_2025.csv --report
"""

import sys
import argparse
import json
from .agent import CSVCompareAgent


def main():
    parser = argparse.ArgumentParser(
        description="CSVCompareAgent - Compare and audit multiple CSV datasets."
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Paths to two or more CSV files to compare."
    )
    parser.add_argument(
        "--key", "-k",
        help="Primary key column for record-level diffing (auto-detected if omitted)."
    )
    parser.add_argument(
        "--report", "-r",
        nargs="?",
        const="comparison_report.md",
        default=None,
        help="Generate a comprehensive Markdown audit report (default: comparison_report.md)."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON comparison metrics to stdout."
    )
    parser.add_argument(
        "--sql",
        help="Run an arbitrary SQL query across the loaded CSV tables."
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Start an interactive query session."
    )

    args = parser.parse_args()

    if len(args.files) < 2 and not args.interactive:
        print("Note: Provide at least 2 CSV files to compare.")

    print(f"Loading {len(args.files)} dataset(s)...")
    agent = CSVCompareAgent(args.files)

    # Summary
    summary = agent.summary()
    print("\n--- Loaded Datasets ---")
    for name, meta in summary.items():
        print(f"[{name}] Rows: {meta['row_count']} | Cols: {meta['column_count']} | Size: {meta['file_size_kb']} KB")
        if meta["candidate_keys"]:
            print(f"       Candidate Keys: {', '.join(meta['candidate_keys'])}")

    # SQL query mode
    if args.sql:
        print(f"\nExecuting SQL: {args.sql}")
        res = agent.sql(args.sql)
        print(json.dumps(res, indent=2, default=str))
        return

    # Full comparison
    if len(args.files) >= 2:
        print("\n--- Schema Comparison ---")
        schema = agent.compare_schemas()
        print(f"Shared Columns ({len(schema['common_columns'])}): {', '.join(schema['common_columns'])}")
        for name, cols in schema["unique_columns_by_file"].items():
            if cols:
                print(f"Columns unique to {name}: {', '.join(cols)}")
        if schema["type_conflicts"]:
            print(f"Type Conflicts: {schema['type_conflicts']}")

        print("\n--- Record Level Audit ---")
        diff = agent.diff_records(key_column=args.key)
        print(f"Key Column: {diff.get('key_column')}")
        print(f"Added Records: {diff.get('added_count')}")
        print(f"Removed Records: {diff.get('removed_count')}")
        print(f"Modified Records: {diff.get('modified_count')}")
        print(f"Unchanged Records: {diff.get('unchanged_count')}")

        if args.json:
            comp = agent.compare_all()
            print("\n--- Full JSON Metrics ---")
            print(json.dumps(comp, indent=2, default=str))

        if args.report:
            out_file = args.report
            agent.generate_markdown_report(out_file)
            print(f"\n[+] Generated Markdown Audit Report: {out_file}")

    if args.interactive:
        print("\n=== Entering CSVCompareAgent Interactive Mode ===")
        print("Type 'help' for commands, or type a question/instruction ('exit' to quit).")
        while True:
            try:
                line = input("\nagent> ").strip()
                if not line:
                    continue
                if line.lower() in ("exit", "quit"):
                    break
                if line.lower() == "help":
                    print("Commands: summary | schema | diff | stats | sql <query> | report <path> | exit")
                    continue
                if line.lower() == "summary":
                    print(json.dumps(agent.summary(), indent=2))
                elif line.lower() == "schema":
                    print(json.dumps(agent.compare_schemas(), indent=2))
                elif line.lower() == "diff":
                    print(json.dumps(agent.diff_records(), indent=2))
                elif line.lower() == "stats":
                    print(json.dumps(agent.compare_statistics(), indent=2))
                elif line.lower().startswith("sql "):
                    query = line[4:].strip()
                    print(json.dumps(agent.sql(query), indent=2, default=str))
                elif line.lower().startswith("report"):
                    parts = line.split(maxsplit=1)
                    target = parts[1] if len(parts) > 1 else "comparison_report.md"
                    agent.generate_markdown_report(target)
                    print(f"Report saved to {target}")
                else:
                    ans = agent.ask(line)
                    print(ans)
            except (KeyboardInterrupt, EOFError):
                break
            except Exception as e:
                print(f"Error: {e}")


if __name__ == "__main__":
    main()

