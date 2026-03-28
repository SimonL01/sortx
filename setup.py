from __future__ import annotations

from setuptools import setup


setup(
    name="sortx",
    version="0.1.0",
    description="Signature-first file classification for DFIR and parser automation.",
    packages=[
        "sortx",
        "sortx.core",
        "sortx.discovery",
        "sortx.settings",
        "sortx.standalones",
        "sortx.utils",
    ],
    package_dir={
        "sortx": ".",
        "sortx.core": "core",
        "sortx.discovery": "discovery",
        "sortx.settings": "settings",
        "sortx.standalones": "standalones",
        "sortx.utils": "utils",
    },
    entry_points={
        "console_scripts": [
            "sortx=sortx.cli:main",
        ]
    },
    python_requires=">=3.12",
    install_requires=[
        "python-magic-bin==0.4.14; platform_system == 'Windows'",
        "python-magic>=0.4.27; platform_system != 'Windows'",
    ],
)
