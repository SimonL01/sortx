from __future__ import annotations

import json
import os
from pathlib import Path

from .models import FrameworkSettings


def load_settings(config_path: str | None = None) -> FrameworkSettings:
    package_dir = Path(__file__).resolve().parent.parent
    if config_path:
        selected_path = Path(config_path).resolve()
    else:
        env_config_path = os.environ.get("SORTX_CONFIG_PATH", "").strip()
        selected_path = (
            Path(env_config_path).expanduser().resolve()
            if env_config_path
            else package_dir / "config.json"
        )

    raw: dict = {}
    if selected_path.exists():
        with selected_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)

    return FrameworkSettings(
        base_dir=package_dir,
        case_root=str(raw.get("case_root", "cases")),
        hashing_algorithm=str(raw.get("hashing", {}).get("algorithm", "sha256")),
    )
