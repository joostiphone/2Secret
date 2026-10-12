#!/usr/bin/env bash
# Fills a 2Secret server with demo data for screenshots.
#
#   seed.sh <server url> <work dir> <en|nl>
#
# Creates a demo account with a personal, a family and a work vault full of
# items, and a second account the family vault is shared with. The demo
# account's e-mail address and Secret Key are written to <work dir>/<lang>/.
# Needs `2secret` on PATH.
set -euo pipefail

server="$1"
lang="$3"
work="$2/$lang"
export TWOSECRET_PASSWORD='correct-horse-battery-staple-42'
mkdir -p "$work"

if [ "$lang" = nl ]; then
  me="Alex de Vries" email=alex@voorbeeld.nl partner="Sam de Vries" partner_email=sam@voorbeeld.nl
  mail=alex.devries@gmail.com family_mail=familie.devries@gmail.com
  personal=Persoonlijk family=Gezin work_vault=Werk
else
  me="Alex Morgan" email=alex@example.com partner="Sam Morgan" partner_email=sam@example.com
  mail=alex.morgan@gmail.com family_mail=morgan.family@gmail.com
  personal=Personal family=Family work_vault=Work
fi
# English and Dutch text: pick by language.
l() { if [ "$lang" = nl ]; then echo "$2"; else echo "$1"; fi; }

create() { # home name email
  TWOSECRET_HOME="$work/$1" 2secret account create --server "$server" --name "$2" --email "$3" \
    < <(printf '%s\n%s\n' "$TWOSECRET_PASSWORD" "$TWOSECRET_PASSWORD") 2>&1 |
    sed -n 's/.*Secret Key: \(2S-[A-Z0-9-]*\).*/\1/p'
}

create partner "$partner" "$partner_email" > /dev/null
create me "$me" "$email" > "$work/secret-key"
echo "$email" > "$work/email"

export TWOSECRET_HOME="$work/me"
eval "$(2secret unlock)"
s() { local out; out=$(2secret "$@" 2>&1) || { echo "$out" >&2; return 1; }; }

[ "$personal" = Personal ] || s vault rename Personal "$personal"
s vault create "$family" --description "$(l "Shared with Sam" "Gedeeld met Sam")"
s vault create "$work_vault"

s add login --title GitHub --username alex.dev --generate --url https://github.com/login \
  --totp JBSWY3DPEHPK3PXP --tag "$(l work werk)" --tag dev --favorite \
  --secret-field "$(l "Recovery codes" "Herstelcodes")=7f3k-29dm, 8x2q-ln4p, 0zr8-q9vb"
s add login --title Google --username "$mail" --generate --url https://accounts.google.com --favorite
s add login --title "$(l Amazon bol.com)" --username "$mail" --password 'Summer2019!' \
  --url "$(l https://www.amazon.com https://www.bol.com)"
s add login --title Netflix --username "$mail" --password 'Summer2019!' --url https://www.netflix.com
s add login --title "$(l "Old forum" "Oud forum")" --username alexm --password 'qwerty12' --url http://forum.example.org
s add login --title Dropbox --username "$mail" --generate --url https://www.dropbox.com
s add credit_card --title "Visa Gold" --field "cardholder=$me" --field number=4111111111111111 \
  --field expiry=09/2029 --field cvv=123 --favorite
s add passport --title "$(l Passport Paspoort)" --field "number=NX4R82J91" --field "expires=2031-04-17"
s add bank_account --title "$(l "Savings account" Spaarrekening)" --field "bank_name=$(l "Example Bank" Voorbeeldbank)" \
  --field "iban=NL91ABNA0417164300" --field "bic=ABNANL2A"
s add wireless_router --title "$(l "Home Wi-Fi" "Wifi thuis")" --field "network_name=$(l Morgan-Home DeVries-Thuis)" --generate
s add secure_note --title "$(l "Spare key" Reservesleutel)" \
  --notes "$(l "Under the blue flower pot by the back door." "Onder de blauwe bloempot bij de achterdeur.")"
s add identity --title "$me" --field "first_name=Alex" --field "last_name=$(l Morgan "de Vries")" \
  --field "email=$mail" --field "phone=+31 6 1234 5678"

s add login --vault "$family" --title Spotify --username "$family_mail" --generate --url https://open.spotify.com
s add login --vault "$family" --title "Disney+" --username "$family_mail" --generate --url https://www.disneyplus.com
s add wireless_router --vault "$family" --title "$(l "Holiday home Wi-Fi" "Wifi vakantiehuis")" \
  --field "network_name=$(l Seaview Zeezicht)" --generate
s add secure_note --vault "$family" --title "$(l "Alarm code" Alarmcode)" --secret-field "Code=4821" \
  --notes "$(l "Panel next to the front door." "Paneel naast de voordeur.")"

s add api_credential --vault "$work_vault" --title "$(l "AWS production" "AWS productie")" \
  --field "username=deploy-bot" --secret-field "credential=AKIA4EXAMPLE7Q2ZL9" --tag "$(l work werk)"
s add database --vault "$work_vault" --title "Postgres (staging)" --field "server=db.staging.internal" \
  --field "port=5432" --field "database=app" --field "username=app" --generate
s add login --vault "$work_vault" --title Slack --username alex@acme.example --generate \
  --url https://acme.slack.com --tag "$(l work werk)"

s vault share "$family" "$partner_email" --role editor
s sync
