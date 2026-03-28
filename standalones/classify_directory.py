from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


if __package__ in {None, ""}:
    project_root = Path(__file__).resolve().parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from sortx.core.case import create_case_context
    from sortx.discovery import build_inventory, materialize_classified_view
    from sortx.settings import load_settings
else:
    from ..core.case import create_case_context
    from ..discovery import build_inventory, materialize_classified_view
    from ..settings import load_settings


def _remove_if_empty(path: Path) -> None:
    if path.exists() and path.is_dir() and not any(path.iterdir()):
        path.rmdir()


def _close_case_logger(context) -> None:
    for handler in list(context.logger.handlers):
        handler.close()
        context.logger.removeHandler(handler)


def _prune_unused_case_dirs(context) -> None:
    empty_log = context.paths.logs_dir / "case.log"
    if empty_log.exists() and empty_log.is_file() and empty_log.stat().st_size == 0:
        empty_log.unlink()

    _remove_if_empty(context.paths.logs_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Classify files from an existing directory without running adapters."
    )
    parser.add_argument(
        "--dir",
        type=str,
        required=True,
        help="Directory containing files to classify.",
    )
    parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="Output directory where the classification workspace will be written.",
    )
    parser.add_argument(
        "--case-name",
        type=str,
        help="Optional case name for the generated workspace.",
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Optional framework JSON config used for hashing settings and paths.",
    )
    args = parser.parse_args(argv)

    source_dir = Path(args.dir).resolve()
    if not source_dir.exists():
        parser.error(f"Source directory does not exist: {source_dir}")
    if not source_dir.is_dir():
        parser.error(f"Source path is not a directory: {source_dir}")

    output_dir = Path(args.out).resolve()
    settings = load_settings(args.config)
    case_name = args.case_name or source_dir.name
    context = create_case_context(
        case_name=case_name,
        source_path=source_dir,
        source_kind="directory",
        settings=settings,
        output_dir=str(output_dir),
    )

    inventory = build_inventory(context, source_dir)
    classified_roots = materialize_classified_view(context, inventory, source_dir)

    summary = {
        "status": "completed",
        "records": len(inventory),
        "tag_counts": dict(Counter(item["primary_tag"] for item in inventory)),
        "family_counts": dict(Counter(item["family"] for item in inventory)),
        "method_counts": dict(Counter(item["classification"]["method"] for item in inventory)),
        "classified_roots": {tag: str(path) for tag, path in sorted(classified_roots.items())},
    }
    context.write_manifest(
        {
            "case_name": context.case_name,
            "source_path": str(context.source_path),
            "source_kind": context.source_kind,
            "inventory_records": len(inventory),
            "tool_runs": [],
            "summary_report": summary,
            "status": "completed",
        }
    )

    summary_path = context.paths.artifacts_dir / "classification-summary.json"
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    _close_case_logger(context)
    _prune_unused_case_dirs(context)

    print(f"Workspace: {context.paths.case_dir}")
    print(f"Inventory: {context.paths.artifacts_dir / 'inventory.json'}")
    print(f"Summary: {summary_path}")
    print(f"Classified files: {context.paths.classified_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
