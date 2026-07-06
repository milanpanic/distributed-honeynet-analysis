#!/usr/bin/env python3
"""
Paired analysis-time comparison for honeynet evaluation.

Purpose:
- Reads 20 paired scenario observations from a CSV file.
- Compares manual analysis time in Configuration A with parser-assisted
  analysis time in Configuration B.
- Calculates descriptive statistics and a paired t-test.
- Writes a text report and a CSV file with paired differences.

CSV input columns required:
run, scenario, manual_time_min, parser_time_min

Interpretation:
Configuration A = standalone Cowrie / manual log analysis
Configuration B = distributed honeynet / parser-assisted normalized analysis
Paired difference = manual_time_min - parser_time_min

"""

from pathlib import Path
import argparse
import math
import pandas as pd

try:
    from scipy import stats
except ImportError:
    stats = None


def cohen_d_paired(differences: pd.Series) -> float:
    """Cohen's dz for paired samples: mean difference / SD difference."""
    return differences.mean() / differences.std(ddof=1)


def format_p_value(p: float) -> str:
    if p < 0.001:
        return "p < 0.001"
    return f"p = {p:.4f}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calculate paired t-test for honeynet analysis-time comparison."
    )
    parser.add_argument(
        "--input",
        default="paired_observations_example.csv",
        help="Input CSV file with paired observations."
    )
    parser.add_argument(
        "--output-report",
        default="paired_ttest_report.txt",
        help="Output text report."
    )
    parser.add_argument(
        "--output-csv",
        default="paired_observations_with_differences.csv",
        help="Output CSV with calculated differences."
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    df = pd.read_csv(input_path)

    required = {"run", "scenario", "manual_time_min", "parser_time_min"}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(f"Missing required CSV columns: {sorted(missing)}")

    df["paired_difference_min"] = df["manual_time_min"] - df["parser_time_min"]

    n = len(df)
    if n < 2:
        raise ValueError("At least two paired observations are required.")

    manual_mean = df["manual_time_min"].mean()
    parser_mean = df["parser_time_min"].mean()
    diff_mean = df["paired_difference_min"].mean()
    diff_sd = df["paired_difference_min"].std(ddof=1)
    diff_se = diff_sd / math.sqrt(n)
    df_degrees = n - 1

    # Paired t-test.
    # The test compares two measurements from the same scenario:
    # manual analysis time vs. parser-assisted analysis time.
    if stats is not None:
        t_stat, p_value = stats.ttest_rel(
            df["manual_time_min"],
            df["parser_time_min"]
        )
        ci_low, ci_high = stats.t.interval(
            confidence=0.95,
            df=df_degrees,
            loc=diff_mean,
            scale=diff_se
        )
    else:
        # If scipy is not installed, calculate the t statistic only.
        # Exact p-value and t-based CI require scipy.
        t_stat = diff_mean / diff_se
        p_value = float("nan")
        ci_low, ci_high = float("nan"), float("nan")

    dz = cohen_d_paired(df["paired_difference_min"])

    report = []
    report.append("Paired analysis-time comparison")
    report.append("=" * 40)
    report.append(f"Number of paired scenario runs: {n}")
    report.append("")
    report.append("Configurations:")
    report.append("A = standalone Cowrie / manual log analysis")
    report.append("B = distributed honeynet / parser-assisted normalized analysis")
    report.append("")
    report.append("Descriptive statistics:")
    report.append(f"Mean time, Configuration A: {manual_mean:.2f} minutes")
    report.append(f"Mean time, Configuration B: {parser_mean:.2f} minutes")
    report.append(f"Mean paired difference A - B: {diff_mean:.2f} minutes")
    report.append(f"SD of paired differences: {diff_sd:.2f}")
    report.append(f"SE of paired differences: {diff_se:.2f}")
    report.append("")
    report.append("Paired t-test:")
    report.append(f"t({df_degrees}) = {t_stat:.2f}")
    if math.isnan(p_value):
        report.append("p-value: not calculated because scipy is not installed")
        report.append("Install scipy with: pip install scipy")
    else:
        report.append(format_p_value(p_value))
        report.append(f"95% CI for mean difference: [{ci_low:.2f}, {ci_high:.2f}] minutes")
    report.append(f"Effect size, Cohen's dz: {dz:.2f}")
    report.append("")
    report.append("Suggested manuscript sentence:")
    report.append(
        f"The mean manual analysis time was {manual_mean:.2f} minutes, "
        f"whereas parser-assisted normalized analysis required {parser_mean:.2f} minutes on average. "
        f"The mean paired reduction was {diff_mean:.2f} minutes "
        f"(SD = {diff_sd:.2f}). A paired t-test confirmed a statistically significant reduction, "
        f"t({df_degrees}) = {t_stat:.2f}, {format_p_value(p_value) if not math.isnan(p_value) else 'p-value not calculated'}."
    )

    Path(args.output_report).write_text("\n".join(report), encoding="utf-8")
    df.to_csv(args.output_csv, index=False)

    print("\n".join(report))
    print("")
    print(f"Saved report to: {args.output_report}")
    print(f"Saved paired differences CSV to: {args.output_csv}")


if __name__ == "__main__":
    main()
