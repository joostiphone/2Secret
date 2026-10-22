#!/usr/bin/env bash
# Starts the simulator build of the iOS app on simulated devices and checks
# that it keeps running, also when it is opened with an otpauth:// link. This
# checks the UIScene life cycle, without which an app built with the iOS 27
# SDK does not start (vendor/README.md). Runs on macOS after
# `scripts/ios-appstore.sh` without an App Store Connect key.
#
#   scripts/ios-simulator-check.sh ["iPhone 17" ["iPad Air 11-inch (M4)" ...]]
#
# For each device it saves a screenshot in ios/build/screenshots and prints a
# small JPEG of it as base64 between "screenshot" markers in the log. A device
# the simulator has no runtime for is skipped with a warning.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
app="$root/ios/build/DerivedData/Build/Products/Debug-iphonesimulator/2Secret.app"
[ -d "$app" ] || { echo "No simulator build at $app; run scripts/ios-appstore.sh first" >&2; exit 1; }
bundle="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Info.plist")"
shots="$root/ios/build/screenshots"
mkdir -p "$shots"
[ $# -gt 0 ] || set -- "iPhone 17"

echo "Device types with a fold or a second display:"
xcrun simctl list devicetypes | grep -iE 'duo|fold' || echo "  (none)"

# Runs a command, but stops it after a number of seconds (macOS has no timeout).
limit() {
  local seconds="$1"
  shift
  perl -e 'alarm shift; exec @ARGV' "$seconds" "$@"
}

running() {
  limit 30 xcrun simctl spawn "$1" launchctl list | grep -F "UIKitApplication:$bundle" | awk '{print $1}' | grep -qE '^[0-9]+$'
}

check() {
  local udid="$1" step="$2"
  sleep 20
  if ! running "$udid"; then
    echo "::error::2Secret stopped on $device ($step)" >&2
    find "$HOME/Library/Logs/DiagnosticReports" -name '2Secret*' -mmin -10 -exec cat {} + 2> /dev/null | head -200 >&2 || true
    limit 120 xcrun simctl spawn "$udid" log show --last 2m --style compact \
      --predicate 'process == "2Secret" OR eventMessage CONTAINS[c] "twosecret"' 2>&1 | tail -80 >&2 || true
    return 1
  fi
  echo "2Secret runs on $device ($step)"
}

# One device at a time: a runner cannot boot several at once.
status=0 checked=0
for device in "$@"; do
  echo "== $device"
  if ! udid="$(xcrun simctl create "2Secret check" "$device")"; then
    echo "::warning::No simulator runtime for $device; skipped"
    continue
  fi
  checked=$((checked + 1))
  echo "Booting"
  xcrun simctl boot "$udid"
  limit 900 xcrun simctl bootstatus "$udid" -b > /dev/null
  echo "Installing"
  limit 300 xcrun simctl install "$udid" "$app"
  name="$(echo "$device" | tr -c 'A-Za-z0-9\n' '-')"

  ok=1
  echo "Starting"
  limit 120 xcrun simctl launch "$udid" "$bundle" > /dev/null || ok=0
  [ "$ok" = 0 ] || check "$udid" "started" || ok=0
  if [ "$ok" = 1 ]; then
    limit 60 xcrun simctl io "$udid" screenshot "$shots/$name.png" > /dev/null
    sips -Z 480 -s format jpeg -s formatOptions 60 "$shots/$name.png" --out "$shots/$name.jpg" > /dev/null
    echo "--- screenshot $device (base64 JPEG) ---"
    base64 < "$shots/$name.jpg" | tr -d '\n'
    echo
    echo "--- end of screenshot ---"
    # A link while the app runs, and one that starts it.
    link="otpauth://totp/Check:simulator?secret=JBSWY3DPEHPK3PXP&issuer=Check"
    echo "Opening a link"
    limit 60 xcrun simctl openurl "$udid" "$link" || ok=0
    [ "$ok" = 0 ] || check "$udid" "link while running" || ok=0
  fi
  if [ "$ok" = 1 ]; then
    echo "Starting with a link"
    limit 60 xcrun simctl terminate "$udid" "$bundle" || true
    for _ in $(seq 15); do running "$udid" || break; sleep 1; done
    limit 60 xcrun simctl openurl "$udid" "$link" || ok=0
    [ "$ok" = 0 ] || check "$udid" "started by a link" || ok=0
  fi
  [ "$ok" = 1 ] || status=1

  limit 120 xcrun simctl shutdown "$udid" || true
  limit 60 xcrun simctl delete "$udid" || true
done
[ "$checked" -gt 0 ] || { echo "::error::No device to start the app on" >&2; exit 1; }
exit "$status"
