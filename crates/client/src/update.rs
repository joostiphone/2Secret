//! Fetching signed updates from the GitHub releases (see
//! [`twosecret_core::update`] for what is verified).

use std::time::Duration;

use twosecret_core::update::{Asset, Update, MANIFEST_URL, MAX_MANIFEST_SIZE, SIGNATURE_URL};

use crate::{Error, Result};

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("2Secret/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        // Installers are large: limit the time without data, not the total.
        .read_timeout(Duration::from_secs(60))
        .https_only(!cfg!(test))
        .build()
        .unwrap_or_default()
}

/// The newest release, verified with the built-in keys. `None` when it has
/// no update manifest.
pub async fn latest() -> Result<Option<Update>> {
    latest_from(MANIFEST_URL, SIGNATURE_URL, &twosecret_core::update::public_keys()).await
}

pub async fn latest_from(manifest_url: &str, signature_url: &str, keys: &[[u8; 32]]) -> Result<Option<Update>> {
    let http = http();
    let Some(json) = get(&http, manifest_url, MAX_MANIFEST_SIZE).await? else { return Ok(None) };
    let signature =
        get(&http, signature_url, 1024).await?.ok_or_else(|| Error::Protocol("the update has no signature".into()))?;
    Ok(Some(Update::verify_with(json, &String::from_utf8_lossy(&signature), keys)?))
}

/// Download an installer from a verified manifest and check it.
pub async fn download(asset: &Asset) -> Result<Vec<u8>> {
    let bytes = get(&http(), &asset.url, asset.size)
        .await?
        .ok_or_else(|| Error::Protocol(format!("{} is missing", asset.name())))?;
    asset.verify(&bytes)?;
    Ok(bytes)
}

/// GET at most `limit` bytes; `None` on 404.
async fn get(http: &reqwest::Client, url: &str, limit: u64) -> Result<Option<Vec<u8>>> {
    let mut response = http.get(url).send().await?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(Error::Api { status: status.as_u16(), code: "http".into(), message: format!("{url}: {status}") });
    }
    let too_large = || Error::Protocol(format!("{url} is larger than expected"));
    if response.content_length().is_some_and(|len| len > limit) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if (body.len() + chunk.len()) as u64 > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use twosecret_core::update::{target, Manifest, RELEASES_URL};

    /// A tiny HTTP server with fixed responses (path → body; others 404).
    fn serve(files: HashMap<&'static str, Vec<u8>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).map(|n| n == 0).unwrap_or(true) || header.trim().is_empty() {
                        break;
                    }
                }
                let mut stream = reader.into_inner();
                let (status, body) = match files.get(path.as_str()) {
                    Some(b) => ("200 OK", b.clone()),
                    None => ("404 Not Found", b"not found".to_vec()),
                };
                let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = stream.write_all(head.as_bytes()).and_then(|_| stream.write_all(&body));
            }
        });
        base
    }

    fn signed(version: &str, installer: &[u8], seed: u8) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            target::LINUX_X64_APPIMAGE.to_string(),
            Asset {
                url: format!("{RELEASES_URL}/download/v{version}/2-secret_{version}_x86_64.AppImage"),
                size: installer.len() as u64,
                sha256: twosecret_core::util::hex(&Sha256::digest(installer)),
            },
        );
        let manifest = Manifest {
            version: version.into(),
            date: String::new(),
            url: format!("{RELEASES_URL}/tag/v{version}"),
            files,
        };
        let json = serde_json::to_vec(&manifest).unwrap();
        let sig = twosecret_core::util::b64(&key.sign(&json).to_bytes()).into_bytes();
        (json, sig, key.verifying_key().to_bytes())
    }

    #[tokio::test]
    async fn fetches_and_verifies() {
        let installer = b"new version".to_vec();
        let (json, sig, key) = signed("9.0.0", &installer, 3);
        let (_, other_sig, _) = signed("9.0.0", &installer, 4);
        let base = serve(HashMap::from([
            ("/update.json", json.clone()),
            ("/update.json.sig", sig),
            ("/forged.sig", other_sig),
            ("/installer", installer.clone()),
            ("/big.json", vec![b' '; MAX_MANIFEST_SIZE as usize + 1]),
        ]));
        let url = |p: &str| format!("{base}{p}");

        let update = latest_from(&url("/update.json"), &url("/update.json.sig"), &[key]).await.unwrap().unwrap();
        assert_eq!(update.json, json);
        assert!(update.manifest.is_newer_than(env!("CARGO_PKG_VERSION")));

        // Wrong signature, no signature, no manifest, oversized manifest.
        assert!(latest_from(&url("/update.json"), &url("/forged.sig"), &[key]).await.is_err());
        assert!(latest_from(&url("/update.json"), &url("/nothing.sig"), &[key]).await.is_err());
        assert!(latest_from(&url("/nothing.json"), &url("/update.json.sig"), &[key]).await.unwrap().is_none());
        assert!(latest_from(&url("/big.json"), &url("/update.json.sig"), &[key]).await.is_err());

        // The download must match the signed size and hash.
        let mut asset = update.manifest.file(target::LINUX_X64_APPIMAGE).unwrap().clone();
        asset.url = url("/installer");
        assert_eq!(download(&asset).await.unwrap(), installer);
        let mut wrong = asset.clone();
        wrong.sha256 = "0".repeat(64);
        assert!(download(&wrong).await.is_err());
        let mut short = asset.clone();
        short.size -= 1;
        assert!(download(&short).await.is_err());
        asset.url = url("/gone");
        assert!(download(&asset).await.is_err());
    }
}
