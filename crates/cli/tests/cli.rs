//! Integration tests that run the real `2secret` binary.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};

const PW: &str = "Vq8#mT2!zL5@pR9$";

fn temp_home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("2secret-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn cli(home: &Path) -> Command {
    let mut c = Command::cargo_bin("2secret").unwrap();
    c.env("TWOSECRET_HOME", home)
        .env("TWOSECRET_INSECURE_TEST_KDF", "1")
        .env("TWOSECRET_PASSWORD", PW)
        .env_remove("TWOSECRET_SESSION");
    c
}

fn create_local(home: &Path) {
    cli(home)
        .args(["account", "create", "--name", "Test", "--email", "test@example.com"])
        .env_remove("TWOSECRET_PASSWORD")
        .write_stdin(format!("{PW}\n{PW}\n"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Secret Key: 2S-"));
}

#[test]
fn local_workflow() {
    let home = temp_home("local");
    create_local(&home);
    cli(&home).args(["status"]).assert().success().stdout(predicate::str::contains("local-only"));

    cli(&home)
        .args([
            "add",
            "login",
            "--title",
            "GitHub",
            "--username",
            "octo",
            "--password",
            "hunter2hunter2",
            "--url",
            "https://github.com",
            "--tag",
            "dev",
            "--totp",
            "JBSWY3DPEHPK3PXP",
            "--field",
            "recovery=abc",
            "--secret-field",
            "pin=1234",
        ])
        .assert()
        .success();
    cli(&home)
        .args([
            "add",
            "credit_card",
            "--title",
            "Visa",
            "--field",
            "number=4111111111111111",
            "--field",
            "expiry=01/2020",
        ])
        .assert()
        .success();

    cli(&home)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("GitHub").and(predicate::str::contains("Visa")));
    cli(&home)
        .args(["list", "--category", "credit_card", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Visa").and(predicate::str::contains("GitHub").not()));
    cli(&home)
        .args(["get", "github"])
        .assert()
        .success()
        .stdout(predicate::str::contains("octo").and(predicate::str::contains("hunter2hunter2").not()));
    cli(&home)
        .args(["get", "github", "--reveal"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hunter2hunter2"));
    cli(&home).args(["get", "GitHub", "--field", "pin"]).assert().success().stdout("1234\n");
    cli(&home).args(["read", "2s://Personal/GitHub/password", "-n"]).assert().success().stdout("hunter2hunter2");
    cli(&home).args(["totp", "GitHub"]).assert().success().stdout(predicate::str::is_match(r"^\d{6}\n$").unwrap());
    cli(&home)
        .args(["inject"])
        .write_stdin("user={{ 2s://GitHub/username }}\n")
        .assert()
        .success()
        .stdout("user=octo\n");

    // Edit: password history is kept.
    cli(&home).args(["edit", "GitHub", "--password", "a-new-password-42"]).assert().success();
    cli(&home).args(["history", "GitHub"]).assert().success().stdout(predicate::str::contains("hunter2hunter2"));

    // Watchtower spots the expired card.
    cli(&home).args(["watchtower", "--json"]).assert().success().stdout(predicate::str::contains("expired"));

    // Trash and restore.
    cli(&home).args(["delete", "Visa"]).assert().success();
    cli(&home).args(["list", "--trash"]).assert().success().stdout(predicate::str::contains("Visa"));
    cli(&home).args(["restore", "Visa"]).assert().success();

    // Vaults.
    cli(&home).args(["vault", "create", "Work"]).assert().success();
    cli(&home).args(["move", "Visa", "--to", "Work"]).assert().success();
    cli(&home).args(["list", "--vault", "work"]).assert().success().stdout(predicate::str::contains("Visa"));
    cli(&home).args(["vault", "list"]).assert().success().stdout(predicate::str::contains("Work"));

    // Wrong password is refused.
    cli(&home)
        .args(["list"])
        .env("TWOSECRET_PASSWORD", "wrong-password")
        .assert()
        .failure()
        .stderr(predicate::str::contains("incorrect master password"));

    // Shell session: unlock once, then no password needed.
    let out = cli(&home).args(["unlock"]).output().unwrap();
    assert!(out.status.success());
    let line = String::from_utf8(out.stdout).unwrap();
    let token = line.split('"').nth(1).unwrap().to_string();
    cli(&home)
        .args(["list"])
        .env_remove("TWOSECRET_PASSWORD")
        .env("TWOSECRET_SESSION", &token)
        .write_stdin("")
        .assert()
        .success()
        .stdout(predicate::str::contains("GitHub"));
    cli(&home).args(["lock"]).assert().success();
    cli(&home)
        .args(["list"])
        .env_remove("TWOSECRET_PASSWORD")
        .env("TWOSECRET_SESSION", &token)
        .write_stdin("not-the-password\n")
        .assert()
        .failure();

    // Encrypted export → import into a fresh account.
    let export = home.join("backup.json");
    cli(&home).args(["export", export.to_str().unwrap()]).write_stdin("export-pass\nexport-pass\n").assert().success();
    let home2 = temp_home("local2");
    create_local(&home2);
    cli(&home2)
        .args(["import", export.to_str().unwrap()])
        .write_stdin("export-pass\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("Imported 2 of 2"));
    cli(&home2).args(["read", "2s://GitHub/password"]).assert().success().stdout("a-new-password-42\n");

    // run: references in the environment are resolved for the child only.
    #[cfg(unix)]
    cli(&home2)
        .args(["run", "--", "sh", "-c", "printf %s \"$DB_PASS\""])
        .env("DB_PASS", "2s://GitHub/password")
        .assert()
        .success()
        .stdout("a-new-password-42");

    cli(&home).args(["account", "forget", "--yes"]).assert().success();
    cli(&home).args(["status"]).assert().success().stdout(predicate::str::contains("No account"));
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&home2);
}

#[test]
fn generator_and_strength() {
    let home = temp_home("gen");
    cli(&home)
        .args(["generate", "--length", "32"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^\S{32}\n$").unwrap());
    cli(&home)
        .args(["generate", "--words", "4", "--separator", "."])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^[a-z\-]+\.[a-z\-]+\.[a-z\-]+\.[a-z\-]+\n$").unwrap());
    cli(&home)
        .args(["generate", "--pin", "8", "--count", "3"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^(\d{8}\n){3}$").unwrap());
    cli(&home).args(["strength", "password"]).assert().success().stdout(predicate::str::contains("Terrible"));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn server_workflow() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let url = rt.block_on(async {
        let state = twosecret_server::AppState::in_memory(Default::default()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(twosecret_server::serve(listener, state));
        url
    });

    let a = temp_home("srv-a");
    let out = cli(&a)
        .args(["--json", "account", "create", "--name", "Alice", "--email", "alice@example.com", "--server", &url])
        .env_remove("TWOSECRET_PASSWORD")
        .write_stdin(format!("{PW}\n{PW}\n"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let sk = v["secret_key"].as_str().unwrap().to_string();

    cli(&a).args(["add", "login", "--title", "Shared Wifi", "--password", "letmein-please-42"]).assert().success();

    let b = temp_home("srv-b");
    cli(&b)
        .args(["account", "signin", "--server", &url, "--email", "alice@example.com", "--secret-key", &sk])
        .assert()
        .success()
        .stderr(predicate::str::contains("1 items"));
    cli(&b).args(["read", "2s://Shared Wifi/password"]).assert().success().stdout("letmein-please-42\n");

    cli(&b).args(["edit", "Shared Wifi", "--password", "changed-on-b-123"]).assert().success();
    cli(&a).args(["sync"]).assert().success();
    cli(&a).args(["read", "2s://Shared Wifi/password"]).assert().success().stdout("changed-on-b-123\n");
    cli(&a).args(["account", "devices"]).assert().success().stdout(predicate::str::contains("this device"));

    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
    drop(rt);
}
