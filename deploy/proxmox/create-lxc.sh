#!/usr/bin/env bash
# Creates a Debian 12 LXC container on a Proxmox VE host and installs the
# 2Secret sync server in it (install.sh). Run as root on the Proxmox host:
#
#   curl -fsSLO https://raw.githubusercontent.com/joostiphone/2Secret/HEAD/deploy/proxmox/create-lxc.sh
#   bash create-lxc.sh --tunnel-token <token from Cloudflare>
#
#   --id N                 Container ID (default: the next free one)
#   --hostname NAME        Default 2secret
#   --storage NAME         Storage for the container's disk (default local-lvm)
#   --template-storage N   Storage with container templates (default local)
#   --disk GB              Default 8
#   --memory MB            Default 1024
#   --cores N              Default 1
#   --bridge NAME          Default vmbr0
#   --vlan N               VLAN tag (default none)
#   --ip CIDR              Static address, e.g. 192.168.1.50/24 (default DHCP)
#   --gateway IP           Gateway for a static address
#
# All other options go to install.sh (see install.sh --help), for example
# --tunnel-token, --storage-mb, --signups-per-ip.
set -euo pipefail

INSTALL_URL=https://raw.githubusercontent.com/joostiphone/2Secret/HEAD/deploy/proxmox/install.sh

id="" hostname=2secret storage=local-lvm template_storage=local disk=8 memory=1024 cores=1 bridge=vmbr0
vlan="" ip=dhcp gateway=""
install_args=()

die() {
  echo "error: $*" >&2
  exit 1
}
say() { echo "==> $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --id) id="${2:?}" && shift ;;
    --hostname) hostname="${2:?}" && shift ;;
    --storage) storage="${2:?}" && shift ;;
    --template-storage) template_storage="${2:?}" && shift ;;
    --disk) disk="${2:?}" && shift ;;
    --memory) memory="${2:?}" && shift ;;
    --cores) cores="${2:?}" && shift ;;
    --bridge) bridge="${2:?}" && shift ;;
    --vlan) vlan="${2:?}" && shift ;;
    --ip) ip="${2:?}" && shift ;;
    --gateway) gateway="${2:?}" && shift ;;
    -h | --help) sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//' && exit 0 ;;
    *) install_args+=("$1") ;;
  esac
  shift
done

[ "$(id -u)" = 0 ] || die "run as root on the Proxmox host"
command -v pct > /dev/null || die "pct not found: run this on a Proxmox VE host"
[ -n "$id" ] || id="$(pvesh get /cluster/nextid)"
! pct status "$id" > /dev/null 2>&1 || die "container $id already exists"

say "Looking for the Debian 12 template"
pveam update > /dev/null || true
template="$(pveam available --section system | awk '{ print $2 }' | grep -E '^debian-12-standard_.*_amd64\.tar\.(zst|gz)$' | sort -V | tail -1)"
[ -n "$template" ] || die "no Debian 12 template available (pveam available --section system)"
if ! pveam list "$template_storage" | grep -q "$template"; then
  say "Downloading $template"
  pveam download "$template_storage" "$template"
fi

net="name=eth0,bridge=$bridge,ip=$ip"
[ -z "$gateway" ] || net+=",gw=$gateway"
[ -z "$vlan" ] || net+=",tag=$vlan"

say "Creating container $id ($hostname)"
# Unprivileged, with nesting for systemd's service sandboxing.
pct create "$id" "$template_storage:vztmpl/$template" \
  --hostname "$hostname" --cores "$cores" --memory "$memory" --swap 512 \
  --rootfs "$storage:$disk" --net0 "$net" --ostype debian \
  --unprivileged 1 --features nesting=1 --onboot 1 \
  --description "2Secret sync server (https://github.com/joostiphone/2Secret)"
pct start "$id"

say "Waiting for the network"
for _ in $(seq 60); do
  pct exec "$id" -- getent hosts github.com > /dev/null 2>&1 && break
  sleep 1
done
pct exec "$id" -- getent hosts github.com > /dev/null 2>&1 || die "container $id has no internet connection"

script="$(dirname "$0")/install.sh"
if [ ! -f "$script" ]; then
  script="$(mktemp)"
  trap 'rm -f "$script"' EXIT
  curl -fsSL --proto '=https' -o "$script" "$INSTALL_URL"
fi
pct push "$id" "$script" /root/2secret-install.sh --perms 0755
pct exec "$id" -- /root/2secret-install.sh "${install_args[@]}"

address="$(pct exec "$id" -- hostname -I | awk '{ print $1 }')"
echo
case " ${install_args[*]} " in
  *" --listen "*) where="on $address:8743" ;;
  *) where="on port 8743 (only inside the container)" ;;
esac
echo "Container $id ($hostname, $address) runs 2Secret $where."
echo "Shell: pct enter $id"
