# Self-hosting the 2Secret server

`2secret-server` is a single binary that provides

- the sync API (`/api/v1/…`) used by all apps, the CLI and the extension,
- the page that opens share links (`/s/…`), and
- (optionally) the **web vault**, so people can use 2Secret from any browser.

It stores only encrypted data (see [SECURITY.md](SECURITY.md)) in a SQLite
database. A small VPS, a Raspberry Pi or a NAS is plenty for a family or team.
The Docker image `ghcr.io/joostiphone/2secret` runs on x86_64 and ARM64
(64-bit Raspberry Pi OS, ARM-based NAS and cloud servers).

Nobody has to run a server: the apps can also use the 2Secret server
(`sync.2secret.app`) or keep the vault on one device. For a server that
others use, on Proxmox with a Cloudflare Tunnel, limits, backups and
automatic updates, see [PUBLIC-SERVER.md](PUBLIC-SERVER.md); its
`deploy/proxmox/install.sh` also sets up any Debian or Ubuntu machine.

## Option 1: Docker Compose with automatic HTTPS (recommended)

1. Point a DNS name (e.g. `vault.example.com`) to your machine.
2. Copy `deploy/docker-compose.yml` and `deploy/Caddyfile`, put your domain in
   the `Caddyfile` and choose an invite code in `docker-compose.yml`.
3. Start it:

   ```sh
   docker compose up -d
   ```

Caddy obtains a Let's Encrypt certificate automatically. Open
`https://vault.example.com` for the web vault, or enter that address in the
desktop/mobile apps, the extension or the CLI.

The compose file gives its network a fixed subnet, so that 2Secret can
believe the client address from Caddy (see [below](#tls--reverse-proxy)).
If you set it up with an older compose file, run `docker compose down` once
before `docker compose up -d`, so the network is made again with that subnet
(the data volume stays).

## Option 2: Docker only

```sh
docker run -d --name 2secret -p 127.0.0.1:8743:8743 -v 2secret-data:/data \
  -e TWOSECRET_SIGNUPS=invite -e TWOSECRET_INVITE_CODES=my-secret-code \
  ghcr.io/joostiphone/2secret:latest
```

To build the image yourself instead: `docker build -t 2secret .`

Put a TLS-terminating reverse proxy in front of it (see below). The proxy's
requests reach the container from Docker's bridge, not from this machine's
loopback address, so also add `-e TWOSECRET_CLIENT_IP_HEADER=X-Forwarded-For
-e TWOSECRET_TRUSTED_PROXIES=172.17.0.1` (the bridge's gateway, see `docker
network inspect bridge`). Publish the port on `127.0.0.1` only, as above:
then only this machine reaches 2Secret through the gateway.

## Option 3: Binary + systemd

```sh
cargo build --release -p twosecret-server
(cd crates/app && dx bundle --platform web --release)   # optional web vault

sudo install -m 755 target/release/2secret-server /usr/local/bin/
sudo mkdir -p /usr/local/share/2secret/web
sudo cp -r crates/app/dist/public/* /usr/local/share/2secret/web/
sudo useradd --system --home /var/lib/2secret 2secret
sudo cp deploy/2secret-server.service /etc/systemd/system/
sudo systemctl enable --now 2secret-server
```

## Configuration

Every option can be given as a command line flag or environment variable.

| Flag | Environment variable | Default | Meaning |
|---|---|---|---|
| `--bind` | `TWOSECRET_BIND` | `127.0.0.1:8743` | Listen address |
| `--data-dir` | `TWOSECRET_DATA_DIR` | `./2secret-data` | Database location |
| `--web-dir` | `TWOSECRET_WEB_DIR` | – | Serve the web vault from this directory |
| `--signups` | `TWOSECRET_SIGNUPS` | `open` | `open`, `invite` or `closed` |
| `--invite-codes` | `TWOSECRET_INVITE_CODES` | – | Comma separated invite codes (for `invite`); the placeholders of the examples (`change-me…`) never work |
| `--session-days` | `TWOSECRET_SESSION_DAYS` | `30` | Sign out devices after this many idle days |
| `--session-max-days` | `TWOSECRET_SESSION_MAX_DAYS` | `365` | Sign out devices after this many days, however often they are used |
| `--cors-origins` | `TWOSECRET_CORS_ORIGINS` | – | Extra origins allowed to call the API from a browser (`*` for any) |
| `--account-storage-mb` | `TWOSECRET_ACCOUNT_STORAGE_MB` | – | Storage per account for everything the server keeps for it: the vaults it owns (shared vaults count for their owner, deleted items too), share links, keys for emergency contacts, agents elsewhere and the profile photo; what does not fit stays on the device |
| `--signups-per-ip` | `TWOSECRET_SIGNUPS_PER_IP` | – | New accounts per client address per day (IPv6: per /64) |
| `--max-accounts` | `TWOSECRET_MAX_ACCOUNTS` | – | Accept no new accounts beyond this number |
| `--client-ip-header` | `TWOSECRET_CLIENT_IP_HEADER` | – | Header with the client's address from a proxy on the same machine or a trusted one: `X-Forwarded-For` (Caddy, nginx), `CF-Connecting-IP` (Cloudflare Tunnel) |
| `--trusted-proxies` | `TWOSECRET_TRUSTED_PROXIES` | – | Proxies on other machines whose header is believed, e.g. cloudflared in another container: `10.0.0.5` or `192.168.1.0/24`, comma separated |
| `--max-agents` | `TWOSECRET_MAX_AGENTS` | `20` | AI agents on other computers one account may pair ([AGENT-PROTOCOL.md](AGENT-PROTOCOL.md)) |
| `--max-agent-requests` | `TWOSECRET_MAX_AGENT_REQUESTS` | `20` | Requests one such agent may have waiting for an answer |

Logging is controlled with `RUST_LOG` (e.g. `RUST_LOG=info`).

**Recommended for a private server:** `--signups invite` with a long invite
code, or `--signups closed` once everyone has an account.

## TLS / reverse proxy

Always use HTTPS. Behind a proxy every request comes from the proxy's
address, so set `TWOSECRET_CLIENT_IP_HEADER=X-Forwarded-For`
(`deploy/2secret-server.service` and `deploy/docker-compose.yml` do).
Without it all clients share the limits per address, and one person's
failed sign-ins block sign-ins for everyone. 2Secret believes the header
only from a proxy on the same machine or in `TWOSECRET_TRUSTED_PROXIES`, and
takes its last address: the one the proxy added.

Example configurations:

**Caddy** (sets `X-Forwarded-For` itself)

```
vault.example.com {
	reverse_proxy 127.0.0.1:8743
}
```

**nginx**

```nginx
server {
    listen 443 ssl http2;
    server_name vault.example.com;
    ssl_certificate     /etc/letsencrypt/live/vault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vault.example.com/privkey.pem;
    client_max_body_size 64m;
    location / {
        proxy_pass http://127.0.0.1:8743;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

## Backups

Everything lives in the data directory:

- `2secret.db` (+ `-wal`/`-shm` while running) – encrypted vaults and items,
  accounts and the per-installation secret.

Back it up with the server stopped, or online with SQLite's backup command:

```sh
sqlite3 /var/lib/2secret/2secret.db ".backup '/backups/2secret-$(date +%F).db'"
```

Server backups contain only encrypted data, but treat them as sensitive
anyway. Users can additionally make their own encrypted exports in the app
(*Settings → Export*).

## Upgrading

Stop the server, replace the binary (or pull the new image) and start it
again. Database migrations run automatically.

## Health check

`GET /api/v1/health` returns `{"status":"ok","version":"…","signups_open":…}`.
