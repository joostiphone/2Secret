"""C compiler for `scripts/cross-check.sh`: `zig cc` for another platform.

Only for type checking (`cargo check` / `cargo clippy`): the objects build
scripts compile here are never linked, so headers of a related target are
good enough. Apple SDK flags are dropped; zig brings its own headers.
"""
import subprocess
import sys

target = sys.argv[1]
args, skip = [], False
for a in sys.argv[2:]:
    if skip:
        skip = False
    elif a in ("-arch", "-isysroot"):
        skip = True
    elif not a.startswith(("--target=", "-mmacosx-version-min=", "-miphoneos-version-min=", "-mios-simulator-version-min=")):
        args.append(a)
sys.exit(subprocess.call([sys.executable, "-m", "ziglang", "cc", "-target", target] + args))
