#!/usr/bin/env bash
# Installs or updates the 2Secret sync server on Debian or Ubuntu: in a
# Proxmox LXC container (create-lxc.sh makes one), a VM or any server. Run
# as root. See docs/PUBLIC-SERVER.md.
#
#   install.sh [options]
#
#   --tunnel-token TOKEN  Connect this machine to a Cloudflare Tunnel
#   --version vX.Y.Z      Install this version instead of the newest
#   --signups MODE        open (default), invite or closed
#   --invite-codes CODES  Comma separated invite codes (with --signups invite)
#   --storage-mb N        Storage per account in MB (default 100, 0 = no limit)
#   --signups-per-ip N    New accounts per address per day (default 5, 0 = no limit)
#   --max-accounts N      Accept no new accounts after N (default: no limit)
#   --ip-header NAME      Header with the client's address, set by the proxy
#                         (default CF-Connecting-IP with a Cloudflare Tunnel,
#                         else none: a client could set the header itself)
#   --listen ADDR         Address to listen on (default 127.0.0.1:8743). With
#                         cloudflared in another container: 0.0.0.0:8743
#   --trusted-proxy IPS   Proxies on other machines whose --ip-header is believed,
#                         comma separated, e.g. the cloudflared container's address
#   --no-web              Do not serve the web vault
#   --no-auto-update      Do not install new versions automatically
#   --update              Only update an installed server (the daily timer)
#   --download-only DIR   Download and verify a release into DIR, change nothing
#
# Sets up: the server as a systemd service (127.0.0.1:8743) with its data in
# /var/lib/2secret, its settings in /etc/2secret/server.env, a database backup
# every night in /var/backups/2secret (kept 14 days), signed automatic updates
# every night, logs kept 14 days, and optionally cloudflared.
set -euo pipefail

REPO=joostiphone/2Secret
# Public keys that sign update.json (crates/core/src/update_keys.txt).
UPDATE_KEYS=(szLMLOdfhjWs5oMdLfeXR23tZEpjEjn1D+lJFRDBWFY=)

BIN=/usr/local/bin/2secret-server
WEB=/usr/local/share/2secret/web
DATA=/var/lib/2secret
CONF=/etc/2secret/server.env
BACKUPS=/var/backups/2secret
SELF=/usr/local/sbin/2secret-install

tunnel_token="" version=latest signups=open invite_codes="" storage_mb=100 signups_per_ip=5
max_accounts="" ip_header="" web=1 auto_update=1 mode=install download_dir=""
listen=127.0.0.1:8743 trusted_proxies=""

die() {
  echo "error: $*" >&2
  exit 1
}
say() { echo "==> $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --tunnel-token) tunnel_token="${2:?}" && shift ;;
    --version) version="${2:?}" && shift ;;
    --signups) signups="${2:?}" && shift ;;
    --invite-codes) invite_codes="${2:?}" && shift ;;
    --storage-mb) storage_mb="${2:?}" && shift ;;
    --signups-per-ip) signups_per_ip="${2:?}" && shift ;;
    --max-accounts) max_accounts="${2:?}" && shift ;;
    --ip-header) ip_header="${2:?}" && shift ;;
    --listen) listen="${2:?}" && shift ;;
    --trusted-proxy) trusted_proxies="${2:?}" && shift ;;
    --no-web) web=0 ;;
    --no-auto-update) auto_update=0 ;;
    --update) mode=update ;;
    --download-only) mode=download && download_dir="${2:?}" && shift ;;
    -h | --help) sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//' && exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
  shift
done
case "$signups" in open | invite | closed) ;; *) die "--signups must be open, invite or closed" ;; esac
[ "$signups" != invite ] || [ -n "$invite_codes" ] || die "--signups invite needs --invite-codes"
for n in "$storage_mb" "$signups_per_ip" ${max_accounts:+"$max_accounts"}; do
  [[ "$n" =~ ^[0-9]+$ ]] || die "not a number: $n"
done
if [ -z "$ip_header" ]; then
  if [ -n "$tunnel_token" ] || systemctl is-enabled --quiet cloudflared 2> /dev/null; then
    ip_header=CF-Connecting-IP
  else
    ip_header=none
  fi
fi

download() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"; }

# update.json must be signed with one of UPDATE_KEYS (Ed25519).
verify_signature() {
  local json="$1" sig="$2" tmp key
  tmp="$(mktemp -d)"
  base64 -d < "$sig" > "$tmp/signature" || die "update.json.sig is not base64"
  for key in "${UPDATE_KEYS[@]}"; do
    # Raw 32-byte key → DER SubjectPublicKeyInfo.
    { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; printf '%s' "$key" | base64 -d; } > "$tmp/key.der"
    if openssl pkeyutl -verify -pubin -keyform DER -inkey "$tmp/key.der" -rawin \
      -in "$json" -sigfile "$tmp/signature" > /dev/null 2>&1; then
      rm -rf "$tmp"
      return 0
    fi
  done
  rm -rf "$tmp"
  die "update.json is not signed with 2Secret's key: not installing"
}

# Download the server and web vault of a release into $1 and check them:
# against the signed update.json, or (releases up to 1.3) SHA256SUMS.
# Sets $release_version.
fetch_release() {
  local dir="$1" base prefix target url sha size file
  if [ "$version" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/v${version#v}"
  fi
  download "$base/update.json" "$dir/update.json"
  download "$base/update.json.sig" "$dir/update.json.sig"
  verify_signature "$dir/update.json" "$dir/update.json.sig"
  release_version="$(jq -er .version "$dir/update.json")"
  [[ "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "unexpected version $release_version"
  prefix="https://github.com/$REPO/releases/download/v$release_version/"
  for target in server-linux-x64 web; do
    [ "$target" = web ] && [ "$web" = 0 ] && continue
    if jq -e --arg t "$target" '.files[$t]' "$dir/update.json" > /dev/null; then
      url="$(jq -er --arg t "$target" '.files[$t].url' "$dir/update.json")"
      sha="$(jq -er --arg t "$target" '.files[$t].sha256' "$dir/update.json")"
      size="$(jq -er --arg t "$target" '.files[$t].size' "$dir/update.json")"
      [[ "$url" == "$prefix"* ]] || die "$target does not come from the v$release_version release"
    else
      # Not in update.json yet: the release's (unsigned) checksums.
      [ -f "$dir/SHA256SUMS" ] || download "$base/SHA256SUMS" "$dir/SHA256SUMS"
      if [ "$target" = web ]; then file="2secret-web-v$release_version.tar.gz"; else file="2secret-v$release_version-x86_64-unknown-linux-gnu.tar.gz"; fi
      url="$prefix$file"
      sha="$(awk -v f="$file" '$2 == f { print $1 }' "$dir/SHA256SUMS")"
      size=""
      [ -n "$sha" ] || die "$file is not in SHA256SUMS"
      echo "note: $target is checked against SHA256SUMS, not the signature (release $release_version)"
    fi
    file="$dir/${url##*/}"
    download "$url" "$file"
    [ -z "$size" ] || [ "$(stat -c %s "$file")" = "$size" ] || die "$file has the wrong size"
    echo "$sha  $file" | sha256sum -c --status || die "$file does not match its checksum"
    if [ "$target" = web ]; then web_archive="$file"; else server_archive="$file"; fi
  done
  say "2Secret $release_version downloaded and verified"
}

installed_version() {
  [ -x "$BIN" ] && "$BIN" --version 2> /dev/null | awk '{ print $2 }' || true
}

# Put the downloaded release in place (the service is restarted by the caller).
install_release() {
  local tmp="$1" dir
  mkdir -p "$tmp/server"
  tar --no-same-owner -xzf "$server_archive" -C "$tmp/server"
  dir="$(find "$tmp/server" -name 2secret-server -type f -print -quit)"
  [ -n "$dir" ] || die "no 2secret-server in the archive"
  install -m 0755 "$dir" "$BIN.new" && mv -f "$BIN.new" "$BIN"
  if [ "$web" = 1 ] && [ -n "${web_archive:-}" ]; then
    rm -rf "$WEB.new" && mkdir -p "$WEB.new"
    # Owned by root, not by whoever built the archive.
    tar --no-same-owner --no-same-permissions -xzf "$web_archive" -C "$WEB.new"
    chown -R root:root "$WEB.new" && chmod -R u=rwX,go=rX "$WEB.new"
    rm -rf "$WEB.old" && { [ ! -d "$WEB" ] || mv "$WEB" "$WEB.old"; } && mv "$WEB.new" "$WEB" && rm -rf "$WEB.old"
  fi
}

backup_now() {
  [ -f "$DATA/2secret.db" ] && /usr/local/sbin/2secret-backup || true
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [ "$mode" = download ]; then
  mkdir -p "$download_dir"
  fetch_release "$download_dir"
  exit 0
fi

[ "$(id -u)" = 0 ] || die "run as root"
[ -f /etc/debian_version ] || die "this script is for Debian and Ubuntu"

if [ "$mode" = update ]; then
  [ -x "$BIN" ] || die "2Secret is not installed; run without --update"
  [ -d "$WEB" ] || web=0
  fetch_release "$tmp"
  current="$(installed_version)"
  newest="$(printf '%s\n%s\n' "$current" "$release_version" | sort -V | tail -1)"
  if [ "$current" = "$release_version" ] || [ "$newest" != "$release_version" ]; then
    say "2Secret $current is up to date"
    exit 0
  fi
  say "Updating 2Secret $current → $release_version"
  backup_now
  install_release "$tmp"
  systemctl restart 2secret-server
  exit 0
fi

say "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl jq openssl sqlite3 tar gzip > /dev/null

fetch_release "$tmp"
id 2secret > /dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin 2secret
install -d -m 0750 -o 2secret -g 2secret "$DATA"
install -d -m 0700 "$BACKUPS"
install -d -m 0750 -g 2secret /etc/2secret
[ ! -x "$BIN" ] || backup_now
install_release "$tmp"
install -m 0755 "$0" "$SELF"

say "Writing $CONF"
{
  echo "# Settings of the 2Secret server (2secret-server --help). After a change:"
  echo "#   systemctl restart 2secret-server"
  echo "TWOSECRET_BIND=$listen"
  echo "TWOSECRET_DATA_DIR=$DATA"
  [ "$web" = 1 ] && echo "TWOSECRET_WEB_DIR=$WEB"
  echo "TWOSECRET_SIGNUPS=$signups"
  [ -z "$invite_codes" ] || echo "TWOSECRET_INVITE_CODES=$invite_codes"
  [ "$storage_mb" = 0 ] || echo "TWOSECRET_ACCOUNT_STORAGE_MB=$storage_mb"
  [ "$signups_per_ip" = 0 ] || echo "TWOSECRET_SIGNUPS_PER_IP=$signups_per_ip"
  [ -z "$max_accounts" ] || echo "TWOSECRET_MAX_ACCOUNTS=$max_accounts"
  [ "$ip_header" = none ] || echo "TWOSECRET_CLIENT_IP_HEADER=$ip_header"
  [ -z "$trusted_proxies" ] || echo "TWOSECRET_TRUSTED_PROXIES=$trusted_proxies"
  echo "RUST_LOG=info,tower_http=warn"
} > "$CONF"
chown root:2secret "$CONF" && chmod 0640 "$CONF"

say "Keeping logs for 14 days"
# The server logs no addresses, but the journal is the machine's; keep it
# short, as the privacy statement says.
install -d -m 0755 /etc/systemd/journald.conf.d
printf '[Journal]\nMaxRetentionSec=14day\n' > /etc/systemd/journald.conf.d/2secret.conf
systemctl restart systemd-journald || true

say "Setting up services"
cat > /etc/systemd/system/2secret-server.service << EOF
[Unit]
Description=2Secret sync server
After=network-online.target
Wants=network-online.target

[Service]
User=2secret
EnvironmentFile=$CONF
ExecStart=$BIN
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/sbin/2secret-backup << 'EOF'
#!/bin/sh
# Back up the 2Secret database (safe while the server runs); keeps 14 days.
set -eu
dir=/var/backups/2secret
file="$dir/2secret-$(date +%Y-%m-%d-%H%M).db"
mkdir -p "$dir" && chmod 700 "$dir"
sqlite3 /var/lib/2secret/2secret.db ".backup '$file'"
gzip -f "$file"
find "$dir" -name '2secret-*.db.gz' -mtime +"${KEEP_DAYS:-14}" -delete
echo "backup: $file.gz"
EOF
chmod 0755 /usr/local/sbin/2secret-backup

cat > /etc/systemd/system/2secret-backup.service << 'EOF'
[Unit]
Description=Back up the 2Secret database

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/2secret-backup
EOF
cat > /etc/systemd/system/2secret-backup.timer << 'EOF'
[Unit]
Description=Back up the 2Secret database every night

[Timer]
OnCalendar=*-*-* 03:15
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/2secret-update.service << EOF
[Unit]
Description=Install a new version of 2Secret (signed releases only)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SELF --update
EOF
cat > /etc/systemd/system/2secret-update.timer << 'EOF'
[Unit]
Description=Look for a new version of 2Secret every night

[Timer]
OnCalendar=*-*-* 04:30
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now 2secret-backup.timer > /dev/null
if [ "$auto_update" = 1 ]; then
  systemctl enable --now 2secret-update.timer > /dev/null
else
  systemctl disable --now 2secret-update.timer > /dev/null 2>&1 || true
fi
systemctl enable 2secret-server > /dev/null
systemctl restart 2secret-server

if [ -n "$tunnel_token" ]; then
  say "Installing cloudflared"
  install -d -m 0755 /usr/share/keyrings
  download https://pkg.cloudflare.com/cloudflare-main.gpg /usr/share/keyrings/cloudflare-main.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
    > /etc/apt/sources.list.d/cloudflared.list
  apt-get update -qq
  apt-get install -y -qq cloudflared > /dev/null
  if [ -f /etc/systemd/system/cloudflared.service ]; then
    echo "note: cloudflared is already set up; to use another tunnel: cloudflared service uninstall, then run this again"
  else
    cloudflared service install "$tunnel_token"
  fi
fi

say "Checking the server"
# Where this machine reaches the server: 0.0.0.0 and [::] listen on every
# address, loopback included.
local_addr="$listen"
case "$listen" in 0.0.0.0:*) local_addr="127.0.0.1:${listen##*:}" ;; "[::]":*) local_addr="[::1]:${listen##*:}" ;; esac
for _ in $(seq 30); do
  if health="$(curl -fsS "http://$local_addr/api/v1/health" 2> /dev/null)"; then
    echo "$health"
    echo
    echo "2Secret $(installed_version) is running."
    echo "  Settings:  $CONF (then: systemctl restart 2secret-server)"
    echo "  Data:      $DATA"
    echo "  Backups:   $BACKUPS (every night, 14 days; copy them elsewhere too)"
    [ "$auto_update" = 1 ] && echo "  Updates:   every night, signed releases only (systemctl list-timers 2secret-*)"
    echo "  Logs:      journalctl -u 2secret-server"
    exit 0
  fi
  sleep 1
done
journalctl -u 2secret-server -n 30 --no-pager || true
die "the server did not start"
