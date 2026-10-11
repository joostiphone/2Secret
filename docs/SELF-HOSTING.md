# Self-hosting the 2Secret server

`2secret-server` is a single binary that provides

- the sync API (`/api/v1/…`) used by all apps, the CLI and the extension, and
- (optionally) the **web vault**, so people can use 2Secret from any browser.

It stores only encrypted data (see [SECURITY.md](SECURITY.md)) in a SQLite
database. A small VPS, a Raspberry Pi or a NAS is plenty for a family or team.

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

## Option 2: Docker only

```sh
docker build -t 2secret .
docker run -d --name 2secret -p 127.0.0.1:8743:8743 -v 2secret-data:/data \
  -e TWOSECRET_SIGNUPS=invite -e TWOSECRET_INVITE_CODES=my-secret-code 2secret
```

Put a TLS-terminating reverse proxy in front of it (see below).

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
| `--invite-codes` | `TWOSECRET_INVITE_CODES` | – | Comma separated invite codes (for `invite`) |
| `--session-days` | `TWOSECRET_SESSION_DAYS` | `30` | Sign out devices after this many idle days |
| `--cors-origins` | `TWOSECRET_CORS_ORIGINS` | – | Extra origins allowed to call the API from a browser (`*` for any) |

Logging is controlled with `RUST_LOG` (e.g. `RUST_LOG=info`).

**Recommended for a private server:** `--signups invite` with a long invite
code, or `--signups closed` once everyone has an account.

## TLS / reverse proxy

Always use HTTPS. Example configurations:

**Caddy**

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
