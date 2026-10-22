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
#
# A link that starts the app is not a check: the simulator then asks "Open in
# 2Secret?", which nobody taps here. The log shows the screen instead.
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

# Prints a small JPEG of a saved screenshot in the log.
show() {
  local name="$1" title="$2"
  sips -Z 480 -s format jpeg -s formatOptions 60 "$shots/$name.png" --out "$shots/$name.jpg" > /dev/null
  echo "--- screenshot $title (base64 JPEG) ---"
  base64 < "$shots/$name.jpg" | tr -d '\n'
  echo
  echo "--- end of screenshot ---"
}

# Saves a screenshot of every display (iPhone Duo has two) and shows it.
screenshot() {
  local udid="$1" name="$2" title="$3" out display displays
  if out="$(limit 60 xcrun simctl io "$udid" screenshot "$shots/$name.png" 2>&1)"; then
    show "$name" "$title"
    return
  fi
  # "Cannot choose between 2 displays" lists them as "--display=3  LCD-1 ...".
  displays="$(printf '%s\n' "$out" | sed -n 's/^ *--display=\([0-9][0-9]*\) .*/\1/p')"
  [ -n "$displays" ] || { printf '%s\n' "$out" >&2; return 1; }
  for display in $displays; do
    limit 60 xcrun simctl io "$udid" screenshot --display="$display" "$shots/$name-$display.png" > /dev/null
    show "$name-$display" "$title, $(printf '%s\n' "$out" | sed -n "s/^ *--display=$display  *//p")"
  done
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
    screenshot "$udid" "$name" "$device"
    echo "Opening a link"
    link="otpauth://totp/Check:simulator?secret=JBSWY3DPEHPK3PXP&issuer=Check"
    limit 60 xcrun simctl openurl "$udid" "$link" || ok=0
    [ "$ok" = 0 ] || check "$udid" "link while running" || ok=0
  fi
  if [ "$ok" = 1 ]; then
    # Not a check (see the top): what the screen shows after a link that
    # should start the app.
    limit 60 xcrun simctl terminate "$udid" "$bundle" || true
    for _ in $(seq 15); do running "$udid" || break; sleep 1; done
    limit 60 xcrun simctl openurl "$udid" "$link" || true
    sleep 10
    screenshot "$udid" "$name-link" "$device after a link that should start the app"
  fi
  [ "$ok" = 1 ] || status=1

  limit 120 xcrun simctl shutdown "$udid" || true
  limit 60 xcrun simctl delete "$udid" || true
done
[ "$checked" -gt 0 ] || { echo "::error::No device to start the app on" >&2; exit 1; }
exit "$status"
