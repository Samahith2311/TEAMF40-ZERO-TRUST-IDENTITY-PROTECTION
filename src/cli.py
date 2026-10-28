import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from src.ingest import run_ingest_all, ingest_file
from src.pipeline import run_pipeline, run_pipeline_slice
from src.harness import run_evaluation_harness, run_mutation_check, load_all_fixtures, run_detectors_on_events, evaluate_level
from src.alerts import verify_evidence_refs
from src.db import get_db, setup_db
from src.config import COLLECTIONS

def main():
    parser = argparse.ArgumentParser(description="Zero Trust Identity Protection Engine CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Ingest
    sub_ingest = subparsers.add_parser("ingest", help="Ingest and normalize log feeds")
    sub_ingest.add_argument("--sources", nargs="*", help="Optional source file paths")

    # Pipeline Slice / Run All
    subparsers.add_parser("run-all", help="Execute complete analysis pipeline")

    # Score (Blind scoring on arbitrary unlabeled events)
    sub_score = subparsers.add_parser("score", help="Score unlabelled raw event files through full pipeline")
    sub_score.add_argument("--input", "-i", type=str, required=True, help="Path to raw event file (json/jsonl) or directory")
    sub_score.add_argument("--identities", type=str, default="fixtures/identities.json", help="Path to identities metadata JSON")
    sub_score.add_argument("--out", "-o", type=str, default=None, help="Optional output JSON path for risk scores")

    # Evaluate
    sub_eval = subparsers.add_parser("eval", help="Run evaluation harness against baseline or custom dataset")
    sub_eval.add_argument("--events", type=str, default=None, help="Optional custom raw events file")
    sub_eval.add_argument("--labels", type=str, default=None, help="Optional custom ground truth labels file")
    sub_eval.add_argument("--split", type=str, default="all", choices=["all", "holdout"], help="Split strategy: 'all' or 'holdout'")
    sub_eval.add_argument("--mutation-check", action="store_true", help="Run mutation test")
    sub_eval.add_argument("--export", type=str, default="eval_report.json", help="Path to export JSON evaluation report")

    sub_evaluate = subparsers.add_parser("evaluate", help="Alias for eval")
    sub_evaluate.add_argument("--events", type=str, default=None, help="Optional custom raw events file")
    sub_evaluate.add_argument("--labels", type=str, default=None, help="Optional custom ground truth labels file")
    sub_evaluate.add_argument("--split", type=str, default="all", choices=["all", "holdout"], help="Split strategy: 'all' or 'holdout'")
    sub_evaluate.add_argument("--mutation-check", action="store_true", help="Run mutation test")
    sub_evaluate.add_argument("--export", type=str, default="eval_report.json", help="Path to export JSON evaluation report")

    # Verify Evidence
    subparsers.add_parser("verify-evidence", help="Re-resolve all cited evidence refs against raw logs")

    args = parser.parse_args()

    if args.command == "ingest":
        rep = run_ingest_all(args.sources)
        print(json.dumps(rep, indent=2))

    elif args.command == "run-all":
        res = run_pipeline_slice()
        print(json.dumps(res, indent=2))

    elif args.command == "score":
        db = setup_db()
        input_path = Path(args.input)
        identities_path = args.identities

        if input_path.is_file():
            ingest_file(str(input_path), db)
        elif input_path.is_dir():
            if not identities_path and (input_path / "identities.json").is_file():
                identities_path = str(input_path / "identities.json")

            event_files = [
                f for f in sorted(input_path.glob("*.json*"))
                if f.name not in ["manifest.json", "labels.json", "identities.json"]
            ]
            for f in event_files:
                ingest_file(str(f), db)
        else:
            print(f"Error: input path '{args.input}' not found.", file=sys.stderr)
            sys.exit(1)

        result = run_pipeline(identities_path=identities_path, db=db)
        output_data = {
            "scored_identities_count": result["scored_identities_count"],
            "risk_scores": result["risk_scores"],
            "alerts_count": result["alerts_count"],
            "elapsed_ms": result["elapsed_ms"]
        }
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2)
            print(f"Scores exported to {args.out}")
        else:
            print(json.dumps(output_data, indent=2))

    elif args.command in ["eval", "evaluate"]:
        if args.mutation_check:
            run_mutation_check()
            print("Mutation check passed successfully.")
        else:
            run_evaluation_harness(eval_split=args.split, verbose=True, export_path=args.export)

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
