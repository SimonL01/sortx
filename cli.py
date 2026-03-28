from __future__ import annotations

import argparse

from .standalones.classify_directory import main as classify_directory_main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sortx",
        description="Signature-first file classification for DFIR and parser automation.",
    )
    subparsers = parser.add_subparsers(dest="command")

    classify_parser = subparsers.add_parser(
        "classify",
        help="Classify a directory into sortx output buckets.",
    )
    classify_parser.add_argument(
        "--dir",
        type=str,
        required=True,
        help="Directory containing files to classify.",
    )
    classify_parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="Output directory where the classification workspace will be written.",
    )
    classify_parser.add_argument(
        "--case-name",
        type=str,
        help="Optional case name for the generated workspace.",
    )
    classify_parser.add_argument(
        "--config",
        type=str,
        help="Optional framework JSON config used for hashing settings and paths.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    if argv and argv[0] == "classify":
        return classify_directory_main(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "classify":
        forwarded_args = ["--dir", args.dir, "--out", args.out]
        if args.case_name:
            forwarded_args.extend(["--case-name", args.case_name])
        if args.config:
            forwarded_args.extend(["--config", args.config])
        return classify_directory_main(forwarded_args)

    return classify_directory_main(argv)
