#!/usr/bin/env python3
"""Audit public evidence or create a deterministic, separately staged export."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from netlab.public_evidence import (
    PublicEvidenceError, RULESET, audit_repository, audit_tree, export_tree,
)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error embeds unrecognized argv values.
        self.exit(2, json.dumps({"safe": False, "ruleset": RULESET,
                                 "error": "Invalid public evidence arguments; use --help."}) + "\n")


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export", help="export named evidence into a new directory")
    export.add_argument("--input", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--source-revision", required=True)
    export.add_argument("--export-date", default="")
    export.add_argument("--provenance-path", default="sanitization-manifest.json")
    audit = commands.add_parser("audit", help="report categories/counts and artifact paths only")
    inputs = audit.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--input", type=Path)
    inputs.add_argument("--repository", type=Path)
    audit.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "export":
            result = export_tree(args.input, args.output, source_revision=args.source_revision,
                                 export_date=args.export_date, provenance_path=args.provenance_path)
        else:
            result = audit_repository(args.repository) if args.repository else audit_tree(args.input)
            if args.report:
                # An explicit report is a new derived artifact. Refuse a
                # collision rather than overwrite an original input file.
                with args.report.open("x", encoding="utf-8") as output:
                    output.write(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n")
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
        return 0 if result.get("safe") is True else 1
    except Exception:
        # Error text and argv may contain precisely the identifier an audit
        # detected. Keep failure logs useful without echoing either.
        print(json.dumps({"safe": False, "ruleset": RULESET,
                          "error": "Public evidence operation refused; inspect inputs privately."}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
