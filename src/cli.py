import argparse
import json
import sys
from typing import List

from src.ingest import run_ingest_all
from src.pipeline import run_pipeline_slice
from src.harness import run_evaluation_harness, run_mutation_check
from src.alerts import verify_evidence_refs
from src.db import get_db
from src.config import COLLECTIONS

def main():
    parser = argparse.ArgumentParser(description="Zero Trust Identity Protection Engine CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Ingest
    sub_ingest = subparsers.add_parser("ingest", help="Ingest and normalize log feeds")
    sub_ingest.add_argument("--sources", nargs="*", help="Optional source file paths")

    # Pipeline Slice / Run All
    subparsers.add_parser("run-all", help="Execute complete analysis pipeline")

    # Eval
    sub_eval = subparsers.add_parser("eval", help="Run evaluation harness against baseline")
    sub_eval.add_argument("--mutation-check", action="store_true", help="Run mutation test")
    sub_eval.add_argument("--export", type=str, default="eval_report.json", help="Path to export JSON evaluation report")

    # Verify Evidence
    subparsers.add_parser("verify-evidence", help="Re-resolve all cited evidence refs against raw logs")

    args = parser.parse_args()

    if args.command == "ingest":
        rep = run_ingest_all(args.sources)
        print(json.dumps(rep, indent=2))

    elif args.command == "run-all":
        res = run_pipeline_slice()
        print(json.dumps(res, indent=2))

    elif args.command == "eval":
        if args.mutation_check:
            run_mutation_check()
            print("Mutation check passed successfully.")
        else:
            run_evaluation_harness(verbose=True, export_path=args.export)

    elif args.command == "verify-evidence":
        db = get_db()
        alerts = list(db[COLLECTIONS["alerts"]].find({}, {"_id": 0}))
        if not alerts:
            run_pipeline_slice()
            alerts = list(db[COLLECTIONS["alerts"]].find({}, {"_id": 0}))
        rep = verify_evidence_refs(alerts, fixtures_dir="fixtures")
        print(json.dumps(rep, indent=2))
        if rep["valid_pct"] < 100.0:
            sys.exit(1)

if __name__ == "__main__":
    main()
