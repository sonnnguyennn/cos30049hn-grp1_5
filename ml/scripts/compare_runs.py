"""Compare accepted LR/RF/XGB full runs without modifying historical results."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from iotguard.evaluation.comparison import compare, load_runs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", required=True, type=Path, action="append")
    parser.add_argument("--out", required=True, type=Path, help="New output directory")
    args = parser.parse_args()
    selection = compare(load_runs(args.runs_dir), args.out)
    print(f"Winner: {selection['winner']}; {len(selection['ranking'])} accepted full runs")
    print(f"Excluded: {selection['excluded']}; TEST used: {selection['TEST_used']}")


if __name__ == "__main__":
    main()
