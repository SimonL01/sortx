from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class FrameworkSettings:
    base_dir: Path
    case_root: str = "cases"
    hashing_algorithm: str = "sha256"

    def resolve_path(self, value: str | None) -> Path | None:
        if not value:
            return None
        candidate = Path(value)
        if candidate.is_absolute():
            return candidate
        return (self.base_dir / candidate).resolve()
