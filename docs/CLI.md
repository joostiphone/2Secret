# `2secret` command line reference

The CLI offers everything the apps do, plus tools to keep secrets out of
scripts, configuration files and CI pipelines.

```
2secret [--home DIR] [--json] [--offline] <command>
```

- `--home` (or `TWOSECRET_HOME`) – data directory (default: the platform's
  application data directory).
- `--json` – machine-readable output.
- `--offline` – never contact the sync server.

## Getting started

```sh
2secret account create                          # local-only account
2secret account create --server https://vault.example.com --invite CODE
2secret account signin --server https://vault.example.com --email me@example.com
2secret account connect --server https://vault.example.com   # upload a local account
2secret account emergency-kit -o kit.html        # printable Emergency Kit
```

## Unlocking

Every command asks for the master password unless the shell is unlocked:

```sh
eval "$(2secret unlock)"            # bash/zsh – stays unlocked for 30 idle minutes
2secret unlock --shell fish | source
2secret unlock --shell powershell | Invoke-Expression
2secret lock
```

For unattended use, `TWOSECRET_PASSWORD` can provide the master password
(prefer a dedicated account with access to only the vault it needs).

## Items

```sh
2secret list [QUERY] [--vault V] [--category login] [--tag T] [--favorites] [--trash]
2secret get ITEM [--reveal] [--field password]
2secret add login --title GitHub --username octocat --generate --url github.com --tag dev
2secret add credit_card --title Visa --field number=4111111111111111 --field expiry=12/2030 --secret-field cvv=123
2secret add secure_note --title "Wifi" --notes "SSID: Home"
2secret add ssh_key --title deploy --generate   # new Ed25519 key, prints the public key
2secret edit ITEM --password - --url https://new.example.com --remove-field "old field"
2secret totp ITEM                    # current one-time code
2secret copy ITEM --field password   # clipboard, cleared after 45 s
2secret history ITEM                 # previous passwords
2secret favorite ITEM [--off]
2secret move ITEM --to Work
2secret attach ITEM ./id-scan.pdf
2secret attachment ITEM id-scan.pdf -o ./scan.pdf
2secret delete ITEM [--permanent]
2secret restore ITEM
2secret empty-trash
```

`ITEM` is a title (case-insensitive), an item id, or the first 8+ characters
of an id. Categories: `login`, `password`, `secure_note`, `credit_card`,
`identity`, `bank_account`, `crypto_wallet`, `software_license`, `ssh_key`,
`api_credential`, `database`, `server`, `wireless_router`, `email_account`,
`passport`, `driver_license`, `membership`, `reward_program`, `document`.

## Vaults and sharing

```sh
2secret vault list
2secret vault create Family --description "Shared with the family"
2secret vault rename Family Familie
2secret vault share Familie partner@example.com --role editor   # viewer | editor | manager
2secret vault members Familie
2secret vault set-role Familie partner@example.com viewer
2secret vault unshare Familie partner@example.com   # also gives the vault a new key
2secret vault rotate-key Familie    # new key on request, e.g. after someone left
2secret vault delete Familie        # owners delete, members leave
```

## Emergency access

Trust someone on the same server with read access to the vaults you own, for
when you cannot give it yourself. They ask for it and get it after the
waiting period, unless you deny it.

```sh
2secret emergency add partner@example.com --wait 7   # 1 to 90 days
2secret emergency list
2secret emergency approve partner@example.com        # give access now
2secret emergency deny partner@example.com           # also ends access given
2secret emergency remove partner@example.com

# As the trusted contact
2secret emergency request alice@example.com
2secret emergency cancel alice@example.com
2secret emergency open alice@example.com             # once access is granted
```

## Share links

Share an item with someone without 2Secret: they open the link in any
browser. The content is end-to-end encrypted with a key that only the link
holds; the server keeps it until the link expires or has been opened as often
as allowed. One-time passwords are left out unless you name them with
`--field`.

```sh
2secret share Wi-Fi                        # works 7 days, any number of views
2secret share Wi-Fi --expires 1d --views 1 # 1h … 30d
2secret share GitHub --field username --field password --no-notes
2secret share Bank --password              # asks for a password the link asks for
2secret shares                             # your links
2secret shares --revoke <id>
```

## Secret references

A secret reference points at one value: `2s://<vault>/<item>/<field>` or
`2s://<item>/<field>`. Spaces and special characters may be percent-encoded
(`2s://My%20Vault/…`). Besides field names you can use `username`, `password`,
`otp` (current one-time code), `url`, `notes` and `title`.

```sh
2secret read 2s://Work/Postgres/password
2secret read -n 2s://GitHub/otp | pbcopy

# Templates: replace {{ 2s://… }} placeholders
echo 'DATABASE_URL=postgres://app:{{ 2s://Work/Postgres/password }}@db/app' | 2secret inject > .env
2secret inject -i config.tpl.yml -o config.yml

# Run a program with secrets in its environment (only the child process sees them)
export DATABASE_PASSWORD=2s://Work/Postgres/password
2secret run -- ./migrate.sh
2secret run --env-file .env.2secret -- npm start
```

## Tools

```sh
2secret generate                     # 20 random characters
2secret generate --length 32 --no-symbols --avoid-ambiguous
2secret generate --words 5 --capitalize --number --separator .
2secret generate --pin 6 --count 3
2secret strength 'correct horse battery staple'
2secret watchtower [--breach-check]
2secret import ~/Downloads/export.1pux [--vault Imported]
2secret import bitwarden.json --format bitwarden
2secret export backup.json           # password-protected (default)
2secret export passwords.csv --format csv
2secret sync
2secret status
```

## Account management

```sh
2secret account info
2secret account change-password
2secret account secret-key
2secret account trust-keys EMAIL     # someone's keys changed: trust the new ones after comparing the fingerprint
2secret account devices
2secret account revoke-device ID
2secret account signout
2secret account reauth               # after the server session expired
2secret account delete-server-account
2secret account forget               # remove all local data from this device
```
