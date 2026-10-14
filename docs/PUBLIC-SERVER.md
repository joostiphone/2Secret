# Running a server for everyone (sync.2secret.app)

The apps offer *2Secret server* (`https://sync.2secret.app`) next to *your
own server* and *only on this device*. This guide sets that server up on
Proxmox VE: a small Debian container, reachable through a Cloudflare Tunnel,
with limits, nightly backups and signed automatic updates. The same scripts
work for any public or private 2Secret server on Debian or Ubuntu.

Everything in a vault is end-to-end encrypted, so neither the server nor its
operator can read passwords. The server (and Cloudflare in front of it) does
see e-mail addresses, IP addresses, when people sync and how much they
store. See [Responsibilities](#responsibilities).

## 1. A Cloudflare Tunnel

The tunnel connects the container to Cloudflare from the inside: no ports
open on your router, and your home address stays hidden.

1. Go to **dash.cloudflare.com → Zero Trust → Networks → Tunnels → Create
   a tunnel**, choose **Cloudflared**, name it `2secret` and save.
2. Under *Install and run a connector* choose **Debian**, and copy the token:
   the long string after `cloudflared service install`. Do not run the
   commands shown; the install script does that.
3. **Next**, add a **public hostname**: subdomain `sync`, domain
   `2secret.app`, service type **HTTP**, URL `localhost:8743`. Save.

Then check two things. **Bot Fight Mode** (*Security → Bots*, for the whole
domain) must be off: it blocks the apps, which are not browsers. **Rocket
Loader** and **Email Address Obfuscation** must be off for `sync.2secret.app`
(a *Rules → Configuration Rule* for that hostname, or the zone settings):
they inject scripts the web vault's security policy refuses. The server
already tells Cloudflare not to cache anything.

## 2. The container

On the Proxmox host, as root:

```sh
curl -fsSLO https://raw.githubusercontent.com/joostiphone/2Secret/HEAD/deploy/proxmox/create-lxc.sh
bash create-lxc.sh --tunnel-token <token>
```

It creates an unprivileged Debian 12 container (1 core, 1 GB memory, 8 GB
disk, DHCP on `vmbr0`, started at boot) and runs
`deploy/proxmox/install.sh` in it. Options: `--id`, `--hostname`,
`--storage`, `--disk`, `--memory`, `--cores`, `--bridge`, `--vlan`, `--ip
192.168.1.50/24 --gateway 192.168.1.1`, and those of install.sh below.

In an existing container or VM, copy `deploy/proxmox/install.sh` there and
run it as root with the same options.

After a minute `https://sync.2secret.app/api/v1/health` answers, and the web
vault opens at `https://sync.2secret.app`.

### cloudflared in another container

If cloudflared already runs in a container of its own, leave out
`--tunnel-token` and let 2Secret listen on its network address, believing
the client address only from the cloudflared container:

```sh
bash create-lxc.sh --listen 0.0.0.0:8743 --trusted-proxy <cloudflared container IP>
```

Point the public hostname at `http://<2Secret container IP>:8743` and give
both containers a fixed address (`--ip`, or a DHCP reservation). Without
`--trusted-proxy` every visitor counts as the cloudflared container, so
`--signups-per-ip` would apply to everyone together. Optionally allow port
8743 only from the cloudflared container with the Proxmox firewall.

## 3. Settings and limits

`install.sh` writes `/etc/2secret/server.env`; change it and run
`systemctl restart 2secret-server`, or run install.sh again with options:

| Option | In server.env | Default here | Meaning |
|---|---|---|---|
| `--signups` | `TWOSECRET_SIGNUPS` | `open` | `open`, `invite` (with `--invite-codes`) or `closed` |
| `--storage-mb` | `TWOSECRET_ACCOUNT_STORAGE_MB` | `100` | Storage per account for the vaults it owns (shared vaults count for their owner); `0` = no limit |
| `--signups-per-ip` | `TWOSECRET_SIGNUPS_PER_IP` | `5` | New accounts per address per day (IPv6 per /64) |
| `--max-accounts` | `TWOSECRET_MAX_ACCOUNTS` | none | No new accounts beyond this number |
| `--ip-header` | `TWOSECRET_CLIENT_IP_HEADER` | `CF-Connecting-IP` | Where the client's address comes from; only believed from a proxy on the machine itself or a `--trusted-proxy` |
| `--listen` | `TWOSECRET_BIND` | `127.0.0.1:8743` | Address to listen on |
| `--trusted-proxy` | `TWOSECRET_TRUSTED_PROXIES` | none | Proxies on other machines whose `--ip-header` is believed |
| `--no-web` | `TWOSECRET_WEB_DIR` | web vault on | Serve the web vault on the same address |

A sync that would exceed the storage limit stores nothing of the overflow:
those changes stay on the device and the app says so; nothing is lost.
Failed sign-ins are limited per account (10 per 15 minutes). People see
their usage under *Settings → Sync*.

## 4. Backups

- **Every night** `2secret-backup` copies the database (safe while the server
  runs) to `/var/backups/2secret`, compressed, and keeps 14 days. Run it any
  time: `2secret-backup`.
- **Proxmox**: *Datacenter → Backup → Add*, the container, daily, mode
  *Snapshot*, with a retention you like. Better still to Proxmox Backup
  Server.
- **Off site**: keep a copy outside the house as well, for example the
  Proxmox backups on a second location, or `/var/backups/2secret` with
  rclone to cloud storage. The database only holds encrypted vaults, but
  treat it as sensitive anyway.

Restoring: `systemctl stop 2secret-server`, then `gunzip -c
/var/backups/2secret/2secret-<date>.db.gz > /var/lib/2secret/2secret.db`,
remove `2secret.db-wal` and `2secret.db-shm` if present, `chown 2secret:
/var/lib/2secret/2secret.db`, `systemctl start 2secret-server`.

The apps also remind people to make their own encrypted backup (*Settings →
Backup & export*), so they keep their data even if a server disappears.

## 5. Updates

Every night `2secret-install --update` looks for a newer release. It
installs it only when the release's `update.json` carries 2Secret's Ed25519
signature (the same check as the apps, see [UPDATES.md](UPDATES.md)) and the
download matches it; it makes a database backup first. Releases up to 1.3
did not list the server in `update.json` yet; for those the checksums from
`SHA256SUMS` are used.

Check with `systemctl list-timers '2secret-*'` and `journalctl -u
2secret-update`; update right away with `2secret-install --update`. Turn
automatic updates off with `--no-auto-update`.

Keep Debian itself up to date as well: `apt update && apt upgrade`, or
`unattended-upgrades`.

## 6. Monitoring

Watch `https://sync.2secret.app/api/v1/health` (for example with Uptime
Kuma, keyword `"ok"`), and the container's disk space. Logs:
`journalctl -u 2secret-server` (requests are not logged, so neither are IP
addresses) and `journalctl -u cloudflared`; install.sh keeps the journal for
14 days. The server forgets the addresses and e-mail addresses its limits
count once their window (a day, or 15 minutes for failed sign-ins) has passed.

## Responsibilities

Running a server for others makes you responsible for it:

- **Availability**: when the server is down, the apps keep working on every
  device and catch up later; only syncing and signing in on new devices
  wait.
- **Backups**: see above. A lost database means people have to set up sync
  again from a device (or from their own backup).
- **Privacy (GDPR)**: you process personal data: e-mail addresses, IP
  addresses (Cloudflare), the size and timing of syncs, who shares vaults
  with whom. Say so in the privacy statement on 2secret.app, with what you
  keep, why and how long, that vault contents are end-to-end encrypted, and
  that Cloudflare is a processor. People delete their server account
  themselves in the app (*Settings → Danger zone*), which removes their data
  from the server.
- **Security**: keep the container, Proxmox and your Cloudflare account up
  to date and protected with two-factor authentication.
