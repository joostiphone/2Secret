#!/usr/bin/env bash
# Builds the iOS app with its AutoFill extension and uploads it to App Store
# Connect (TestFlight / App Store). Runs on macOS with Xcode.
#
#   scripts/ios-appstore.sh [version] [build number]
#
# Needs Rust, XcodeGen (`brew install xcodegen`) and, to sign and upload, an
# App Store Connect API key with the App Manager role:
#   APPLE_TEAM_ID                 10-character Team ID
#   APP_STORE_CONNECT_KEY_ID      the key's ID
#   APP_STORE_CONNECT_ISSUER_ID   the issuer ID shown above the keys
#   APP_STORE_CONNECT_KEY         the contents of AuthKey_<id>.p8
# Xcode then creates certificates, app IDs (with the app group and AutoFill)
# and profiles itself. Without the key the app is only built for the
# simulator, which checks that everything compiles.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
version="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)}"
version="${version#v}"
build="${2:-$(date -u +%Y%m%d%H%M)}"

if [ -n "${APP_STORE_CONNECT_KEY:-}" ]; then
  target=aarch64-apple-ios profile=release
else
  target=aarch64-apple-ios-sim profile=debug
fi
cd "$root"
rustup target add "$target" > /dev/null
# The system libraries the Rust code needs; rustc only prints them when it
# compiles the crate, hence the touch.
touch crates/app/src/lib.rs
flags=(-p twosecret-app --lib --crate-type staticlib --target "$target" --no-default-features --features mobile)
[ "$profile" = release ] && flags+=(--release)
libs="$(cargo rustc --color never "${flags[@]}" -- --print native-static-libs 2>&1 | tee /dev/stderr \
  | sed -n 's/.*native-static-libs: //p' | tail -1 | sed $'s/\x1b\\[[0-9;]*m//g')"
[ -f "target/$target/$profile/libtwosecret_app.a" ] || { echo "libtwosecret_app.a was not built" >&2; exit 1; }

cd ios
xcodegen generate --quiet
settings=(
  RUST_LIB_DIR="$root/target/$target/$profile"
  RUST_NATIVE_LIBS="$libs"
  MARKETING_VERSION="$version"
  CURRENT_PROJECT_VERSION="$build"
)

if [ "$profile" = debug ]; then
  xcodebuild build -project TwoSecret.xcodeproj -scheme 2Secret -configuration Debug \
    -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' ARCHS=arm64 \
    CODE_SIGNING_ALLOWED=NO "${settings[@]}"
  echo "Built for the simulator (no App Store Connect key, nothing uploaded)."
  exit 0
fi

mkdir -p build
key="$PWD/build/AuthKey.p8"
printf '%s\n' "$APP_STORE_CONNECT_KEY" > "$key"
trap 'rm -f "$key"' EXIT
auth=(
  -allowProvisioningUpdates
  -authenticationKeyPath "$key"
  -authenticationKeyID "$APP_STORE_CONNECT_KEY_ID"
  -authenticationKeyIssuerID "$APP_STORE_CONNECT_ISSUER_ID"
)
xcodebuild archive -project TwoSecret.xcodeproj -scheme 2Secret -configuration Release \
  -destination 'generic/platform=iOS' -archivePath build/2Secret.xcarchive \
  DEVELOPMENT_TEAM="$APPLE_TEAM_ID" "${settings[@]}" "${auth[@]}"
cat > build/ExportOptions.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key><string>app-store-connect</string>
  <key>destination</key><string>upload</string>
  <key>teamID</key><string>$APPLE_TEAM_ID</string>
  <key>signingStyle</key><string>automatic</string>
  <key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
PLIST
xcodebuild -exportArchive -archivePath build/2Secret.xcarchive \
  -exportOptionsPlist build/ExportOptions.plist -exportPath build/export "${auth[@]}"
echo "Uploaded 2Secret $version ($build) to App Store Connect; it appears in TestFlight after processing."
