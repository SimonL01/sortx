from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path

from sortx.core.case import CaseContext
from sortx.utils import hash_file

from .classifier import classify_file


def build_inventory(context: CaseContext, source_root: Path) -> list[dict]:
    inventory: list[dict] = []
    for file_path in sorted(path for path in source_root.rglob("*") if path.is_file()):
        relative_path = file_path.relative_to(source_root)
        classification = classify_file(file_path)
        stat = file_path.stat()
        inventory.append(
            {
                "relative_path": str(relative_path),
                "absolute_path": str(file_path.resolve()),
                "primary_tag": classification.tag,
                "family": classification.family,
                "description": classification.description,
                "classification": classification.to_dict(),
                "size_bytes": stat.st_size,
                "modified_epoch": int(stat.st_mtime),
                "sha256": hash_file(file_path, context.settings.hashing_algorithm),
            }
        )
    inventory_path = context.paths.artifacts_dir / "inventory.json"
    with inventory_path.open("w", encoding="utf-8") as handle:
        json.dump(inventory, handle, indent=2)

    summary = {
        "tag_counts": Counter(item["primary_tag"] for item in inventory),
        "family_counts": Counter(item["family"] for item in inventory),
        "method_counts": Counter(item["classification"]["method"] for item in inventory),
    }
    with (context.paths.artifacts_dir / "inventory-summary.json").open(
        "w", encoding="utf-8"
    ) as handle:
        json.dump(summary, handle, indent=2)

    return inventory


def materialize_classified_view(
    context: CaseContext,
    inventory: list[dict],
    source_root: Path,
) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for entry in inventory:
        tag = entry["primary_tag"]
        relative_path = Path(entry["relative_path"])
        source_file = source_root / relative_path
        target_file = context.paths.classified_dir / tag / relative_path
        target_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, target_file)
        roots.setdefault(tag, context.paths.classified_dir / tag)
    return roots
