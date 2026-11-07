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

    print("\n[3] Generating Markdown Audit Report...")
    agent.generate_markdown_report("data/exploit_signals_comparison_report.md")
    print("  Report written to: data/exploit_signals_comparison_report.md")


if __name__ == "__main__":
    main()

