"""Create a validation-only freeze, or run inference against that frozen model."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iotguard.evaluation.primary_final_evaluation import final_evaluate, freeze_model


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("freeze")
    freeze.add_argument("--selection", type=Path, required=True)
    freeze.add_argument("--package", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--freeze", type=Path, required=True)
    evaluate.add_argument("--package", type=Path, required=True)
    evaluate.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "freeze":
        result = freeze_model(args.selection, args.package, args.output)
        print(f"FROZEN: {result['selected_run_id']}; TEST opened: {result['TEST_opened']}")
    else:
        result = final_evaluate(args.freeze, args.package, args.out)
        print(result["status"], result["metrics"])


if __name__ == "__main__":
    main()
