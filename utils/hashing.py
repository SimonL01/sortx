from __future__ import annotations

import hashlib
from pathlib import Path


def hash_file(file_path: Path, algorithm: str = "sha256") -> str:
    hasher = hashlib.new(algorithm)
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
