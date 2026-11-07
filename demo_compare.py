"""
Demo script showcasing CSVCompareAgent comparing the newly imported Datathon datasets.
"""

from csv_compare_agent import CSVCompareAgent


def main():
    print("Initializing CSVCompareAgent...")
    # Example: Comparing exploit_signals_2024 and exploit_signals_2025
    agent = CSVCompareAgent(
        file_paths=[
            "data/exploit_signals_2024.csv",
            "data/exploit_signals_2025.csv"
        ],
        aliases=["signals_2024", "signals_2025"]
    )

    print("\n[1] Dataset Summary:")
    summary = agent.summary()
    for name, s in summary.items():
        print(f"  {name}: {s['row_count']} rows, {s['column_count']} cols, {s['file_size_kb']} KB")

    print("\n[2] Schema Comparison:")
    schema = agent.compare_schemas()
    print(f"  Common columns: {schema['common_columns']}")
    print(f"  Type conflicts: {schema['type_conflicts']}")

    print("\n[3] EPSS Version-Aware Comparison (pre-v4 vs v4):")
    epss_comp = agent.compare_epss("signals_2024", "signals_2025", pre_v4_weight=0.6, v4_release_month="2025-03")
    for ds_name, stats in epss_comp["datasets"].items():
        print(f"  [{ds_name}] Raw Mean: {stats['mean_raw_epss']} -> Weighted Mean: {stats['mean_weighted_epss']} (v4 rows: {stats['v4_records']}, pre-v4 rows: {stats['pre_v4_records']})")

    print("\n[4] Generating Markdown Audit Report...")
    agent.generate_markdown_report("data/exploit_signals_comparison_report.md")
    print("  Report written to: data/exploit_signals_comparison_report.md")


if __name__ == "__main__":
    main()

