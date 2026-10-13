#!/usr/bin/env python3
"""Print update.json for the release files in a folder: per platform, the
installer the apps update themselves with, with its size and SHA-256.

    scripts/update-manifest.py out v1.3.0 > out/update.json

scripts/sign-update.sh runs this and signs the result.
"""
import datetime
import hashlib
import json
import os
import re
import sys

# Platform name (see twosecret_core::update::target) → end of the file name.
PLATFORMS = {
    "windows-x64": r"_x64-setup\.exe",
    "macos-arm64": r"_aarch64\.dmg",
    "macos-x64": r"_x64\.dmg",
    "linux-x64-appimage": r"_x86_64\.AppImage",
    "android-arm64": r"_android-arm64\.apk",
}


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    folder, tag = sys.argv[1], sys.argv[2]
    version = tag[1:] if tag.startswith("v") else tag
    releases = f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'joostiphone/2Secret')}/releases"
    files = {}
    for name in sorted(os.listdir(folder)):
        for platform, ending in PLATFORMS.items():
            if not re.search(re.escape(version) + ending + "$", name):
                continue
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name):
                sys.exit(f"unexpected file name: {name}")
            if platform in files:
                sys.exit(f"more than one file for {platform}")
            with open(os.path.join(folder, name), "rb") as f:
                data = f.read()
            files[platform] = {
                "url": f"{releases}/download/v{version}/{name}",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
    if not files:
        sys.exit(f"no installers for {version} in {folder}")
    manifest = {
        "version": version,
        "date": datetime.date.today().isoformat(),
        "url": f"{releases}/tag/v{version}",
        "files": files,
    }
    json.dump(manifest, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
