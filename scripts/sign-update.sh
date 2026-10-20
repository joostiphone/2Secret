#!/usr/bin/env bash
# Writes update.json for the release files in a folder and signs it with the
# Ed25519 private key (PEM) in $UPDATE_SIGNING_KEY, into update.json.sig, and
# SHA256SUMS (if there) into SHA256SUMS.sig. The
# signature is then checked against the public keys built into the apps
# (crates/core/src/update_keys.txt): a release is never signed with a key the
# apps would reject. Needs OpenSSL 3. See docs/UPDATES.md.
#
#   UPDATE_SIGNING_KEY="$(cat key.pem)" scripts/sign-update.sh out v1.3.0
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <folder> <tag>" >&2; exit 2; }
dir="$1" tag="$2"
root="$(cd "$(dirname "$0")/.." && pwd)"
: "${UPDATE_SIGNING_KEY:?set UPDATE_SIGNING_KEY to the private signing key (PEM)}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 "$root/scripts/update-manifest.py" "$dir" "$tag" > "$tmp/update.json"
(umask 077 && printf '%s\n' "$UPDATE_SIGNING_KEY" > "$tmp/key.pem")
openssl pkeyutl -sign -inkey "$tmp/key.pem" -rawin -in "$tmp/update.json" -out "$tmp/signature"
# The checksums of every file, for the downloads that are no update (.deb,
# .rpm, the extension, the CLI): docs/UPDATES.md, "Checking a download".
if [ -f "$dir/SHA256SUMS" ]; then
  openssl pkeyutl -sign -inkey "$tmp/key.pem" -rawin -in "$dir/SHA256SUMS" -out "$tmp/sums.sig"
fi
rm "$tmp/key.pem"

valid=""
while read -r key; do
  case "$key" in "" | "#"*) continue ;; esac
  # Raw 32-byte Ed25519 key → DER SubjectPublicKeyInfo.
  { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; printf '%s' "$key" | openssl base64 -d -A; } > "$tmp/public.der"
  if openssl pkeyutl -verify -pubin -keyform DER -inkey "$tmp/public.der" -rawin \
    -in "$tmp/update.json" -sigfile "$tmp/signature" > /dev/null 2>&1; then
    valid=1
  fi
done < "$root/crates/core/src/update_keys.txt"
if [ -z "$valid" ]; then
  echo "error: UPDATE_SIGNING_KEY does not belong to a public key in crates/core/src/update_keys.txt" >&2
  exit 1
fi

cp "$tmp/update.json" "$dir/update.json"
openssl base64 -A -in "$tmp/signature" > "$dir/update.json.sig"
[ ! -f "$tmp/sums.sig" ] || openssl base64 -A -in "$tmp/sums.sig" > "$dir/SHA256SUMS.sig"
cat "$dir/update.json"
echo "Signed: $dir/update.json.sig"
