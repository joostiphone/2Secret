//! The Emergency Kit: a printable document with everything (except the
//! master password) needed to sign in on a new device.

use crate::crypto::SecretKey;

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// Plain-text Emergency Kit.
pub fn text(name: &str, email: &str, server: Option<&str>, secret_key: &SecretKey) -> String {
    format!(
        "2SECRET EMERGENCY KIT\n\
         =====================\n\n\
         Keep this document somewhere safe (printed, in a safe). Anyone with this\n\
         kit AND your master password can open your vaults.\n\n\
         Name:            {name}\n\
         E-mail:          {email}\n\
         Server:          {server}\n\
         Secret Key:      {sk}\n\
         Master password: ______________________________\n\n\
         To sign in on a new device: open 2Secret, choose \"Sign in\", and enter\n\
         the server address, your e-mail address, the Secret Key above and your\n\
         master password. 2Secret cannot recover a lost master password or\n\
         Secret Key for you.\n",
        server = server.unwrap_or("(local only – no sync server)"),
        sk = secret_key.formatted()
    )
}

/// Printable HTML Emergency Kit.
pub fn html(name: &str, email: &str, server: Option<&str>, secret_key: &SecretKey) -> String {
    let server = server.unwrap_or("Local only (no sync server)");
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>2Secret Emergency Kit</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:720px;margin:40px auto;padding:0 24px;color:#111}}
h1{{font-size:28px;margin:0 0 4px;display:flex;align-items:center;gap:12px}} .brand{{color:#0a8f96}} p.lead{{color:#555;margin-top:0}}
.box{{border:2px solid #111;border-radius:12px;padding:20px 24px;margin:24px 0}}
.row{{display:flex;justify-content:space-between;gap:16px;padding:10px 0;border-bottom:1px solid #ddd}}
.row:last-child{{border-bottom:none}} .label{{color:#555;font-size:13px;text-transform:uppercase;letter-spacing:.05em}}
.value{{font-weight:600;word-break:break-all;text-align:right}}
.sk{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:18px;letter-spacing:.04em}}
.blank{{border-bottom:1px solid #111;min-width:280px;height:22px}}
ol li{{margin:6px 0}} .warn{{background:#fff4e5;border-radius:8px;padding:12px 16px}}
@media print{{body{{margin:0}} .noprint{{display:none}}}}
</style></head><body>
<h1>{logo}<span><span class="brand">2Secret</span> Emergency Kit</span></h1>
<p class="lead">Created for {name}</p>
<div class="box">
<div class="row"><span class="label">E-mail</span><span class="value">{email}</span></div>
<div class="row"><span class="label">Sign-in address</span><span class="value">{server}</span></div>
<div class="row"><span class="label">Secret Key</span><span class="value sk">{sk}</span></div>
<div class="row"><span class="label">Master password</span><span class="blank"></span></div>
</div>
<div class="warn"><strong>Keep this kit safe.</strong> Print it and store it with your important documents. Together with your master password it unlocks all your data. 2Secret cannot recover a lost master password or Secret Key.</div>
<h3>Signing in on a new device</h3>
<ol><li>Install 2Secret or open the web vault.</li><li>Choose <em>Sign in to an existing account</em>.</li>
<li>Enter the sign-in address, your e-mail address, the Secret Key and your master password.</li></ol>
<p class="noprint"><button onclick="window.print()">Print</button></p>
</body></html>"#,
        name = escape(name),
        email = escape(email),
        server = escape(server),
        sk = escape(&secret_key.formatted()),
        logo = crate::brand::tile_svg(44),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn kit_contains_details() {
        let sk = crate::crypto::SecretKey::generate();
        let h = super::html("Jan <x>", "jan@example.com", Some("https://vault.example.com"), &sk);
        assert!(h.contains(&sk.formatted()));
        assert!(h.contains("Jan &lt;x&gt;"));
        let t = super::text("Jan", "jan@example.com", None, &sk);
        assert!(t.contains("local only"));
    }
}
