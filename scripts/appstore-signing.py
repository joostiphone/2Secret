#!/usr/bin/env python3
"""Signing for the App Store build, through the App Store Connect API.

    scripts/appstore-signing.py <output folder>

Makes sure there is an Apple Distribution certificate and App Store
provisioning profiles for the app and its AutoFill extension, and writes
them to the folder for scripts/ios-appstore.sh:

    distribution.p12          the certificate with its private key
    app.mobileprovision       profile for io.github.joostiphone.twosecret
    autofill.mobileprovision  profile for io.github.joostiphone.twosecret.autofill
    signing.env               P12_PASSWORD, APP_PROFILE, AUTOFILL_PROFILE and
                              the profiles' UUIDs, as shell assignments

Needs APP_STORE_CONNECT_KEY_ID, APP_STORE_CONNECT_ISSUER_ID and
APP_STORE_CONNECT_KEY (a key with the Admin role, which may create
certificates) and the Python package `cryptography`.

The certificate's private key is derived from the API key, so every run
finds the certificate an earlier run made instead of making another one:
Apple allows only a few distribution certificates per team, and build
machines keep nothing between runs. A new one is made when it is about to
expire or when the API key changes. The profiles are made anew every run.
"""
import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import shlex
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

API = "https://api.appstoreconnect.apple.com/v1"
BUNDLES = {
    "app": ("io.github.joostiphone.twosecret", "2Secret-AppStore-CI"),
    "autofill": ("io.github.joostiphone.twosecret.autofill", "2Secret-AutoFill-AppStore-CI"),
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def api_key_der() -> bytes:
    """The .p8 key's bytes, whatever whitespace the secret was pasted with."""
    pem = os.environ["APP_STORE_CONNECT_KEY"]
    body = "".join(line.strip() for line in pem.strip().splitlines() if line.strip() and "-----" not in line)
    return base64.b64decode(body)


class Api:
    def __init__(self, key_der: bytes):
        self.key = serialization.load_der_private_key(key_der, None)
        self.key_id = os.environ["APP_STORE_CONNECT_KEY_ID"].strip()
        self.issuer = os.environ["APP_STORE_CONNECT_ISSUER_ID"].strip()

    def token(self) -> str:
        now = int(time.time())
        header = {"alg": "ES256", "kid": self.key_id, "typ": "JWT"}
        claims = {"iss": self.issuer, "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"}
        signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
        r, s = decode_dss_signature(self.key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
        return f"{signing_input}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def call(self, method: str, path: str, body=None, query=None):
        url = API + path + ("?" + urllib.parse.urlencode(query) if query else "")
        request = urllib.request.Request(
            url,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.token()}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
        except urllib.error.HTTPError as e:
            sys.exit(f"App Store Connect API: {method} {path}: HTTP {e.code}\n{e.read().decode(errors='replace')}")
        return json.loads(data) if data else None


class Drbg:
    """Deterministic byte stream (HMAC-SHA-512 in counter mode)."""

    def __init__(self, seed: bytes):
        self.seed, self.counter, self.buffer = seed, 0, b""

    def read(self, n: int) -> bytes:
        while len(self.buffer) < n:
            block = self.counter.to_bytes(8, "big")
            self.buffer += hmac.new(self.seed, b"2secret/ios-distribution-key/" + block, hashlib.sha512).digest()
            self.counter += 1
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out


SMALL_PRIMES = [p for p in range(3, 3000, 2) if all(p % d for d in range(3, math.isqrt(p) + 1, 2))]


def probable_prime(n: int, drbg: Drbg) -> bool:
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for _ in range(40):
        a = 2 + int.from_bytes(drbg.read(len(n.to_bytes((n.bit_length() + 7) // 8, "big")) + 8), "big") % (n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def prime(drbg: Drbg, bits: int, e: int) -> int:
    while True:
        candidate = int.from_bytes(drbg.read(bits // 8), "big") | (3 << (bits - 2)) | 1
        if math.gcd(e, candidate - 1) == 1 and probable_prime(candidate, drbg):
            return candidate


def derived_key(api_key: bytes) -> rsa.RSAPrivateKey:
    """RSA-2048 key derived from the API key (the same on every run)."""
    drbg = Drbg(hmac.new(b"2secret ios distribution certificate v1", api_key, hashlib.sha256).digest())
    e = 65537
    p = prime(drbg, 1024, e)
    q = prime(drbg, 1024, e)
    while q == p:
        q = prime(drbg, 1024, e)
    d = pow(e, -1, (p - 1) * (q - 1))
    public = rsa.RSAPublicNumbers(e, p * q)
    return rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p), public).private_key()


def certificate(api: Api, key: rsa.RSAPrivateKey) -> tuple[str, x509.Certificate]:
    """Our Apple Distribution certificate: the existing one or a new one."""
    modulus = key.public_key().public_numbers().n
    soon = datetime.now(timezone.utc) + timedelta(days=30)
    found = api.call("GET", "/certificates", query={"filter[certificateType]": "DISTRIBUTION", "limit": "200"})
    for item in found["data"]:
        content = item["attributes"].get("certificateContent")
        if not content:
            continue
        cert = x509.load_der_x509_certificate(base64.b64decode(content))
        public = cert.public_key()
        if isinstance(public, rsa.RSAPublicKey) and public.public_numbers().n == modulus and cert.not_valid_after_utc > soon:
            print(f"Using Apple Distribution certificate {item['id']} (valid until {cert.not_valid_after_utc:%Y-%m-%d})")
            return item["id"], cert
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "2Secret App Store build")]))
        .sign(key, hashes.SHA256())
    )
    created = api.call(
        "POST",
        "/certificates",
        {
            "data": {
                "type": "certificates",
                "attributes": {
                    "certificateType": "DISTRIBUTION",
                    "csrContent": csr.public_bytes(serialization.Encoding.PEM).decode(),
                },
            }
        },
    )["data"]
    print(f"Created Apple Distribution certificate {created['id']}")
    return created["id"], x509.load_der_x509_certificate(base64.b64decode(created["attributes"]["certificateContent"]))


def profile(api: Api, identifier: str, name: str, certificate_id: str) -> tuple[str, bytes]:
    """A new App Store provisioning profile for a bundle ID."""
    found = api.call("GET", "/bundleIds", query={"filter[identifier]": identifier, "limit": "200"})
    bundle = next((b for b in found["data"] if b["attributes"]["identifier"] == identifier), None)
    if bundle is None:
        sys.exit(f"The bundle ID {identifier} is not registered (docs/APP-STORE.md, 'Identifiers').")
    for old in api.call("GET", "/profiles", query={"filter[name]": name, "limit": "200"})["data"]:
        api.call("DELETE", f"/profiles/{old['id']}")
    created = api.call(
        "POST",
        "/profiles",
        {
            "data": {
                "type": "profiles",
                "attributes": {"name": name, "profileType": "IOS_APP_STORE"},
                "relationships": {
                    "bundleId": {"data": {"type": "bundleIds", "id": bundle["id"]}},
                    "certificates": {"data": [{"type": "certificates", "id": certificate_id}]},
                },
            }
        },
    )["data"]["attributes"]
    print(f"Created provisioning profile {name} for {identifier}")
    return created["uuid"], base64.b64decode(created["profileContent"])


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    key_der = api_key_der()
    api = Api(key_der)
    key = derived_key(key_der)
    certificate_id, cert = certificate(api, key)

    password = secrets.token_hex(16)
    # Legacy encryption: macOS's `security import` does not read newer PKCS #12.
    encryption = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password.encode())
    )
    with open(os.path.join(out, "distribution.p12"), "wb") as f:
        f.write(pkcs12.serialize_key_and_certificates(b"2Secret distribution", key, cert, None, encryption))

    env = {"P12_PASSWORD": password}
    for kind, (identifier, name) in BUNDLES.items():
        uuid, content = profile(api, identifier, name, certificate_id)
        with open(os.path.join(out, f"{kind}.mobileprovision"), "wb") as f:
            f.write(content)
        env[f"{kind.upper()}_PROFILE"] = name
        env[f"{kind.upper()}_PROFILE_UUID"] = uuid
    with open(os.path.join(out, "signing.env"), "w") as f:
        f.writelines(f"{k}={shlex.quote(v)}\n" for k, v in env.items())


if __name__ == "__main__":
    main()
