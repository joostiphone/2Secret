#!/usr/bin/env bash
# Signs the macOS app that `dx bundle` made and packages it as a .dmg. With a
# Developer ID it also adds the AutoFill extension (macos/), which fills
# passwords and passkeys in Safari and other apps, and has Apple notarize the
# app and the .dmg. Runs on macOS with Xcode; the release workflow calls it.
#
#   scripts/macos-sign.sh <2Secret.app> <output .dmg>
#
# Environment (all optional; see CONTRIBUTING.md, "Signing the macOS app"):
#   APPLE_CERTIFICATE             Developer ID Application certificate with
#   APPLE_CERTIFICATE_PASSWORD    its key (.p12, base64) and its password
#   APPLE_TEAM_ID                 10-character Team ID
#   APP_STORE_CONNECT_KEY_ID      App Store Connect API key: provisioning
#   APP_STORE_CONNECT_ISSUER_ID   profiles for AutoFill (scripts/appstore.py)
#   APP_STORE_CONNECT_KEY         and notarization
#   APPLE_ID, APPLE_PASSWORD      notarize with an Apple ID instead of the key
#
# Without a Developer ID the app is signed ad hoc and has no AutoFill: the
# extension's entitlement needs a provisioning profile, which needs one.
set -euo pipefail

app="$1"
dmg="$2"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
keychain="$work/signing.keychain-db"
old_keychains="$(security list-keychains -d user | tr -d '"')"
cleanup() {
  # shellcheck disable=SC2086
  security list-keychains -d user -s $old_keychains
  security delete-keychain "$keychain" 2> /dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

have_key() {
  [ -n "${APP_STORE_CONNECT_KEY:-}" ] && [ -n "${APP_STORE_CONNECT_KEY_ID:-}" ] && [ -n "${APP_STORE_CONNECT_ISSUER_ID:-}" ]
}

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1" 2> /dev/null || true
}

# Has Apple notarize a file, waiting at most $2 seconds. Returns 0 when Apple
# accepted it, 1 while it is still in progress: the first submissions of a new
# team can take Apple days. Gatekeeper then finds the ticket online once Apple
# accepts it, only not stapled. Stops the build when Apple rejects the file.
notarize() {
  local auth
  if [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_PASSWORD:-}" ]; then
    auth=(--apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$team")
  else
    auth=(--key "$work/AuthKey.p8" --key-id "$APP_STORE_CONNECT_KEY_ID" --issuer "$APP_STORE_CONNECT_ISSUER_ID")
  fi
  local name out id status deadline=$((SECONDS + $2))
  name="$(basename "$1")"
  out="$(xcrun notarytool submit "$1" "${auth[@]}" --output-format json)" || true
  echo "$out"
  id="$(echo "$out" | json_field id)"
  if [ -z "$id" ]; then
    echo "::error::$name could not be submitted for notarization"
    exit 1
  fi
  while :; do
    status="$(xcrun notarytool info "$id" "${auth[@]}" --output-format json 2> /dev/null | json_field status)"
    case "$status" in
      Accepted)
        echo "Notarized: $name"
        return 0
        ;;
      Invalid | Rejected)
        xcrun notarytool log "$id" "${auth[@]}" || true
        echo "::error::Notarization of $name failed: $status"
        exit 1
        ;;
    esac
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "::warning::Apple has not finished notarizing $name (submission $id: ${status:-no answer}). It is not stapled; Gatekeeper finds the ticket online once Apple accepts it"
      return 1
    fi
    sleep 30
  done
}

package() {
  mkdir -p "$work/dmg" "$(dirname "$dmg")"
  cp -R "$app" "$work/dmg/"
  ln -s /Applications "$work/dmg/Applications"
  hdiutil create -volname 2Secret -srcfolder "$work/dmg" -ov -format UDZO "$dmg"
}

if [ -z "${APPLE_CERTIFICATE:-}" ]; then
  # Without a Developer ID, sign ad hoc: a downloaded app with an unsigned
  # bundle is reported as "damaged", an ad-hoc signed one can be allowed in
  # System Settings → Privacy & Security.
  codesign --force --deep --sign - "$app"
  codesign --verify --deep --strict --verbose=2 "$app"
  package
  exit 0
fi

# The Developer ID certificate in a temporary keychain.
keychain_password="$(openssl rand -hex 24)"
echo "$APPLE_CERTIFICATE" | base64 --decode > "$work/certificate.p12"
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$work/certificate.p12" -k "$keychain" -P "${APPLE_CERTIFICATE_PASSWORD:-}" -T /usr/bin/codesign
rm "$work/certificate.p12"
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" > /dev/null
# shellcheck disable=SC2086
security list-keychains -d user -s "$keychain" $old_keychains
line="$(security find-identity -v -p codesigning "$keychain" | grep '"Developer ID Application: ' | head -1 || true)"
if [ -z "$line" ]; then
  echo "::error::APPLE_CERTIFICATE contains no 'Developer ID Application' certificate"
  exit 1
fi
sha1="$(echo "$line" | awk '{ print $2 }')"
identity="$(echo "$line" | sed 's/.*"\(Developer ID Application: .*\)"/\1/')"
team="${APPLE_TEAM_ID:-$(echo "$identity" | sed -n 's/.*(\([A-Z0-9]*\))$/\1/p')}"
echo "Signing with: $identity"
have_key && printf '%s\n' "$APP_STORE_CONNECT_KEY" > "$work/AuthKey.p8"

# By the certificate's SHA-1: a name could match another certificate, and the
# profiles only allow this one.
sign() {
  codesign --force --options runtime --timestamp --sign "$sha1" "$@"
}

# The AutoFill extension: built for the app's architecture, with Developer ID
# provisioning profiles for the app and the extension (they allow the AutoFill
# entitlement). The app and the extension share an app group, which on macOS
# starts with the Team ID; the app's Rust code and the extension read it from
# their Info.plist (TwoSecretAppGroup).
add_autofill() {
  # Runs as an `if` condition, where `set -e` does not apply: every step
  # returns on failure itself.
  command -v xcodegen > /dev/null || brew install xcodegen || return 1
  python3 -c 'import cryptography' 2> /dev/null || {
    python3 -m venv "$work/venv" && "$work/venv/bin/pip" install --quiet cryptography && PATH="$work/venv/bin:$PATH"
  } || return 1
  local info="$app/Contents/Info.plist" exe archs version build kind
  exe="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$info")" || return 1
  archs="$(lipo -archs "$app/Contents/MacOS/$exe")" || return 1
  python3 "$root/scripts/appstore.py" developer-id "$work/profiles" "$sha1" "${archs// /-}" || return 1
  # A claimed entitlement the profile does not allow stops the whole app at
  # launch, which signing does not notice: check before using them.
  local allowed=':Entitlements:com.apple.developer.authentication-services.autofill-credential-provider'
  for kind in app autofill; do
    if ! security cms -D -i "$work/profiles/$kind.provisionprofile" > "$work/$kind-profile.plist" ||
      ! /usr/libexec/PlistBuddy -c "Print $allowed" "$work/$kind-profile.plist" > /dev/null; then
      echo "The $kind profile does not allow AutoFill (enable 'AutoFill Credential Provider' for the App ID)"
      return 1
    fi
  done
  version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$info")" || return 1
  build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$info")" || return 1
  (cd "$root/macos" && xcodegen generate --quiet) || return 1
  xcodebuild build -quiet -project "$root/macos/TwoSecretMac.xcodeproj" -target AutoFill -configuration Release \
    ARCHS="$archs" ONLY_ACTIVE_ARCH=NO SYMROOT="$work/xcode" \
    MARKETING_VERSION="$version" CURRENT_PROJECT_VERSION="$build" || return 1

  local appex="$app/Contents/PlugIns/AutoFill.appex" group="$team.io.github.joostiphone.twosecret"
  mkdir -p "$app/Contents/PlugIns" && rm -rf "$appex" &&
    ditto "$work/xcode/Release/AutoFill.appex" "$appex" &&
    cp "$work/profiles/app.provisionprofile" "$app/Contents/embedded.provisionprofile" &&
    cp "$work/profiles/autofill.provisionprofile" "$appex/Contents/embedded.provisionprofile" &&
    plutil -replace TwoSecretAppGroup -string "$group" "$info" &&
    plutil -replace TwoSecretAppGroup -string "$group" "$appex/Contents/Info.plist" || return 1

  entitlements() {
    cat << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.application-identifier</key><string>$team.$1</string>
  <key>com.apple.developer.team-identifier</key><string>$team</string>
  <key>com.apple.developer.authentication-services.autofill-credential-provider</key><true/>
  <key>com.apple.security.application-groups</key><array><string>$group</string></array>
  <key>keychain-access-groups</key><array><string>$group</string></array>
$2
</dict>
</plist>
PLIST
  }
  entitlements io.github.joostiphone.twosecret "" > "$work/app.entitlements" || return 1
  # App extensions must run in the sandbox.
  entitlements io.github.joostiphone.twosecret.autofill \
    '  <key>com.apple.security.app-sandbox</key><true/>' > "$work/autofill.entitlements" || return 1

  # Inside out: nested code, the extension, then the app.
  local item
  if [ -d "$app/Contents/Frameworks" ]; then
    while IFS= read -r -d '' item; do
      sign "$item" || return 1
    done < <(find "$app/Contents/Frameworks" -depth \( -name '*.dylib' -o -name '*.framework' \) -print0)
  fi
  sign --entitlements "$work/autofill.entitlements" "$appex" || return 1
  sign --entitlements "$work/app.entitlements" "$app" || return 1
  codesign --display --entitlements - "$appex"
}

autofill=0
if have_key && [ -n "$team" ]; then
  if add_autofill; then
    autofill=1
  else
    echo "::warning::The AutoFill extension could not be added (see above); the app is signed without it"
    rm -rf "$app/Contents/PlugIns/AutoFill.appex" "$app/Contents/embedded.provisionprofile"
    rmdir "$app/Contents/PlugIns" 2> /dev/null || true
    plutil -remove TwoSecretAppGroup "$app/Contents/Info.plist" 2> /dev/null || true
  fi
else
  echo "::warning::No App Store Connect API key: the app is signed without the AutoFill extension"
fi
[ "$autofill" = 1 ] || sign --deep "$app"
codesign --verify --deep --strict --verbose=2 "$app"

# Notarize the app, then the disk image, which also has a ticket for the app
# inside. When Apple is still busy with the app, the disk image only gets
# submitted.
notarized=0
if { [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_PASSWORD:-}" ]; } || have_key; then
  ditto -c -k --keepParent "$app" "$work/app.zip"
  if notarize "$work/app.zip" 1200; then
    xcrun stapler staple "$app"
    notarized=1
  else
    notarized=pending
  fi
fi

package
codesign --force --timestamp --sign "$sha1" "$dmg"
if [ "$notarized" = 1 ]; then
  if notarize "$dmg" 1200; then
    xcrun stapler staple "$dmg"
    spctl --assess --type open --context context:primary-signature --verbose "$dmg"
  fi
elif [ "$notarized" = pending ]; then
  notarize "$dmg" 0 || true
fi
