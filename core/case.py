from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from sortx.settings import FrameworkSettings
from sortx.utils import ensure_directory, safe_case_name

from .logging_utils import build_case_logger


@dataclass(slots=True)
class CasePaths:
    case_dir: Path
    logs_dir: Path
    classified_dir: Path
    artifacts_dir: Path


@dataclass(slots=True)
class CaseContext:
    case_name: str
    source_path: Path
    source_kind: str
    settings: FrameworkSettings
    paths: CasePaths
    logger: logging.Logger
    manifest_path: Path

    def write_manifest(self, payload: dict) -> None:
        with self.manifest_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)


def create_case_context(
    *,
    case_name: str,
    source_path: Path,
    source_kind: str,
    settings: FrameworkSettings,
    output_dir: str | None = None,
) -> CaseContext:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    normalized_name = safe_case_name(case_name)

    if output_dir:
        case_dir = Path(output_dir).resolve()
    else:
        case_root = settings.resolve_path(settings.case_root)
        assert case_root is not None
        case_dir = case_root / f"{normalized_name}-{timestamp}"

    logs_dir = ensure_directory(case_dir / "logs")
    classified_dir = ensure_directory(case_dir / "classified")
    artifacts_dir = ensure_directory(case_dir / "artifacts")
    manifest_path = case_dir / "manifest.json"
    logger = build_case_logger(logs_dir / "case.log")

    context = CaseContext(
        case_name=normalized_name,
        source_path=source_path.resolve(),
        source_kind=source_kind,
        settings=settings,
        paths=CasePaths(
            case_dir=case_dir,
            logs_dir=logs_dir,
            classified_dir=classified_dir,
            artifacts_dir=artifacts_dir,
        ),
        logger=logger,
        manifest_path=manifest_path,
    )

    context.write_manifest(
        {
            "case_name": normalized_name,
            "source_path": str(context.source_path),
            "source_kind": source_kind,
            "created_at_utc": timestamp,
            "paths": {key: str(value) for key, value in asdict(context.paths).items()},
            "tool_runs": [],
            "status": "initialized",
        }
    )
    return context
