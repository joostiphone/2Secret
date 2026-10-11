//! Item commands.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use clap::Args;
use serde_json::json;
use twosecret_core::generator::GeneratorOptions;
use twosecret_core::item::{Attachment, Category, Field, FieldKind, Item};
use twosecret_core::session::{ItemFilter, Session};
use twosecret_core::totp::Totp;
use twosecret_core::util::format_timestamp;

use crate::context::{prompt_secret, Ctx};
use crate::output::{mask, print_json, table};
use crate::ItemOpts;

#[derive(Args)]
pub struct ListArgs {
    /// Search text.
    query: Option<String>,
    #[arg(long)]
    vault: Option<String>,
    /// Category, e.g. login, credit_card, secure_note.
    #[arg(long)]
    category: Option<String>,
    #[arg(long)]
    tag: Option<String>,
    #[arg(long)]
    favorites: bool,
    /// List the trash.
    #[arg(long)]
    trash: bool,
}

#[derive(Args)]
pub struct GetArgs {
    item: String,
    #[arg(long)]
    vault: Option<String>,
    /// Print only this field's value.
    #[arg(long, short)]
    field: Option<String>,
    /// Show concealed values.
    #[arg(long)]
    reveal: bool,
}

#[derive(Args)]
pub struct AddArgs {
    /// Category: login, password, secure_note, credit_card, identity, …
    category: String,
    #[arg(long)]
    vault: Option<String>,
    #[command(flatten)]
    opts: ItemOpts,
}

#[derive(Args)]
pub struct EditArgs {
    item: String,
    #[command(flatten)]
    opts: ItemOpts,
    /// Remove a field by label or id (repeatable).
    #[arg(long)]
    remove_field: Vec<String>,
    /// Remove all URLs before adding the given ones.
    #[arg(long)]
    clear_urls: bool,
    /// Remove the favorite mark.
    #[arg(long)]
    unfavorite: bool,
}

fn vault_id(session: &Session, vault: Option<&str>) -> Result<Option<String>> {
    Ok(match vault {
        Some(v) => Some(session.find_vault(v)?.id),
        None => None,
    })
}

pub fn find<'a>(session: &'a Session, query: &str, vault: Option<&str>) -> Result<&'a Item> {
    let vid = vault_id(session, vault)?;
    match session.find_item(query, vid.as_deref()) {
        Ok(i) => Ok(i),
        Err(e) => {
            // Fall back to a unique search match.
            let hits = session.list(&ItemFilter { vault_id: vid, query: query.to_string(), ..Default::default() });
            if hits.len() == 1 {
                Ok(session.item(&hits[0].id).expect("listed"))
            } else if hits.len() > 1 {
                let names: Vec<String> =
                    hits.iter().take(10).map(|h| format!("{} ({})", h.title, &h.id[..8])).collect();
                Err(anyhow!("'{query}' matches several items: {}", names.join(", ")))
            } else {
                Err(e.into())
            }
        }
    }
}

pub fn list(ctx: &Ctx, args: ListArgs) -> Result<()> {
    let mut session = ctx.unlock()?;
    ctx.refresh(&mut session)?;
    let category = match &args.category {
        Some(c) => Some(Category::parse(c).ok_or_else(|| anyhow!("unknown category '{c}'"))?),
        None => None,
    };
    let filter = ItemFilter {
        vault_id: vault_id(&session, args.vault.as_deref())?,
        category,
        favorites_only: args.favorites,
        trashed: args.trash,
        tag: args.tag,
        query: args.query.unwrap_or_default(),
    };
    let items = session.list(&filter);
    if ctx.json {
        print_json(&items);
        return Ok(());
    }
    let vault_names: std::collections::HashMap<String, String> =
        session.vaults().into_iter().map(|v| (v.id, v.name)).collect();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|i| {
            vec![
                i.id[..8].to_string(),
                format!("{}{}", if i.favorite { "★ " } else { "" }, i.title),
                i.subtitle.clone(),
                i.category.name().to_string(),
                vault_names.get(&i.vault_id).cloned().unwrap_or_default(),
            ]
        })
        .collect();
    table(&["id", "title", "details", "category", "vault"], &rows);
    if items.is_empty() {
        eprintln!("No items found.");
    }
    Ok(())
}

pub fn get(ctx: &Ctx, args: GetArgs) -> Result<()> {
    let mut session = ctx.unlock()?;
    ctx.refresh(&mut session)?;
    let item = find(&session, &args.item, args.vault.as_deref())?;
    if let Some(field) = &args.field {
        let reference =
            twosecret_core::secret_ref::SecretRef { vault: None, item: item.id.clone(), field: field.clone() };
        let value = reference.resolve(&session)?;
        println!("{}", *value);
        return Ok(());
    }
    if ctx.json {
        let mut v = serde_json::to_value(item)?;
        v["vault_id"] = json!(session.item_vault(&item.id));
        if !args.reveal {
            if let Some(fields) = v["fields"].as_array_mut() {
                for f in fields {
                    if f["kind"] == "concealed" || f["kind"] == "totp" {
                        f["value"] = json!(mask(f["value"].as_str().unwrap_or("")));
                    }
                }
            }
            v["password_history"] = json!([]);
            if let Some(atts) = v["attachments"].as_array_mut() {
                for a in atts {
                    a["data"] = json!(null);
                }
            }
        }
        print_json(&v);
        return Ok(());
    }
    print_item(&session, item, args.reveal);
    Ok(())
}

fn print_item(session: &Session, item: &Item, reveal: bool) {
    let vault = session.item_vault(&item.id).and_then(|v| session.vault(v)).map(|v| v.name).unwrap_or_default();
    println!("{}{}", item.title, if item.favorite { "  ★" } else { "" });
    println!("{} · {} · {}", item.category.name(), vault, item.id);
    if item.is_trashed() {
        println!("(in trash)");
    }
    println!();
    let mut section = String::new();
    for f in &item.fields {
        if f.value.is_empty() {
            continue;
        }
        if f.section != section {
            section = f.section.clone();
            if !section.is_empty() {
                println!("\n[{section}]");
            }
        }
        let value = match f.kind {
            FieldKind::Totp => match Totp::parse(&f.value) {
                Ok(t) => {
                    let (code, left) = t.now();
                    format!("{} ({left}s)", Totp::format_code(&code))
                }
                Err(_) => "(invalid one-time password secret)".into(),
            },
            FieldKind::Concealed if !reveal => mask(&f.value),
            _ => f.value.clone(),
        };
        if value.contains('\n') {
            println!("{}:", f.label);
            for line in value.lines() {
                println!("    {line}");
            }
        } else {
            println!("{:<20} {}", format!("{}:", f.label), value);
        }
    }
    for url in &item.urls {
        println!("{:<20} {}", "website:", url);
    }
    if !item.tags.is_empty() {
        println!("{:<20} {}", "tags:", item.tags.join(", "));
    }
    if !item.notes.is_empty() {
        println!("\nnotes:");
        for line in item.notes.lines() {
            println!("    {line}");
        }
    }
    if !item.attachments.is_empty() {
        println!("\nattachments:");
        for a in &item.attachments {
            println!("    {} ({} bytes)", a.name, a.size);
        }
    }
    println!();
    println!("created {} · modified {}", format_timestamp(item.created_at), format_timestamp(item.updated_at));
}

fn apply_opts(item: &mut Item, opts: &ItemOpts) -> Result<()> {
    if let Some(t) = &opts.title {
        item.title = t.clone();
    }
    if let Some(u) = &opts.username {
        item.set_value("username", u);
    }
    if opts.generate {
        let pw = GeneratorOptions::random(opts.length).generate();
        set_password(item, &pw);
    } else if let Some(p) = &opts.password {
        let pw = if p == "-" { prompt_secret("Password: ")? } else { p.clone() };
        set_password(item, &pw);
    }
    item.urls.extend(opts.urls.iter().cloned());
    if let Some(n) = &opts.notes {
        item.notes = n.clone();
    }
    item.tags.extend(opts.tags.iter().cloned());
    if let Some(t) = &opts.totp {
        Totp::parse(t)?;
        item.set_value("totp", t);
        if let Some(f) = item.field_mut("totp") {
            f.kind = FieldKind::Totp;
        }
    }
    for (list, concealed) in [(&opts.fields, false), (&opts.secret_fields, true)] {
        for spec in list {
            let (label, value) =
                spec.split_once('=').ok_or_else(|| anyhow!("fields are given as label=value, got '{spec}'"))?;
            let (label, value) = (label.trim(), value.trim());
            if item.field(label).is_some() {
                item.set_value(label, value);
                if concealed {
                    if let Some(f) = item.field_mut(label) {
                        f.kind = FieldKind::Concealed;
                    }
                }
            } else {
                let kind = if concealed { FieldKind::Concealed } else { FieldKind::Text };
                item.fields.push(Field::custom(label, kind, value));
            }
        }
    }
    if opts.favorite {
        item.favorite = true;
    }
    Ok(())
}

fn set_password(item: &mut Item, pw: &str) {
    let key = if item.field("password").is_some() {
        "password"
    } else if item.field("wireless_password").is_some() {
        "wireless_password"
    } else if item.field("credential").is_some() {
        "credential"
    } else {
        item.fields.push(Field::new("password", "password", FieldKind::Concealed, ""));
        "password"
    };
    item.set_value(key, pw);
}

pub fn add(ctx: &Ctx, args: AddArgs) -> Result<()> {
    let category = Category::parse(&args.category).ok_or_else(|| {
        anyhow!(
            "unknown category '{}'. Available: {}",
            args.category,
            Category::ALL.iter().map(|c| c.id()).collect::<Vec<_>>().join(", ")
        )
    })?;
    let mut session = ctx.unlock()?;
    let vault = match &args.vault {
        Some(v) => session.find_vault(v)?.id,
        None => session.default_vault_id().ok_or_else(|| anyhow!("no writable vault"))?,
    };
    let mut item = Item::new(category, "");
    apply_opts(&mut item, &args.opts)?;
    if item.title.trim().is_empty() && item.urls.is_empty() {
        bail!("give the item a --title");
    }
    let id = session.add_item(&vault, item)?;
    ctx.after_write(&mut session)?;
    if ctx.json {
        print_json(&json!({"id": id}));
    } else {
        let item = session.item(&id).expect("just added");
        eprintln!("Created '{}' ({id}).", item.title);
        if args.opts.generate {
            eprintln!("A new password was generated. Copy it with: 2secret copy {}", &id[..8]);
        }
    }
    Ok(())
}

pub fn edit(ctx: &Ctx, args: EditArgs) -> Result<()> {
    let mut session = ctx.unlock()?;
    let mut item = find(&session, &args.item, None)?.clone();
    if args.clear_urls {
        item.urls.clear();
    }
    for name in &args.remove_field {
        let lower = name.to_lowercase();
        let before = item.fields.len();
        item.fields.retain(|f| f.id != *name && f.label.to_lowercase() != lower);
        if before == item.fields.len() {
            bail!("the item has no field '{name}'");
        }
    }
    apply_opts(&mut item, &args.opts)?;
    if args.unfavorite {
        item.favorite = false;
    }
    let title = item.title.clone();
    session.update_item(item)?;
    ctx.after_write(&mut session)?;
    eprintln!("Saved '{title}'.");
    Ok(())
}

pub fn delete(ctx: &Ctx, query: &str, permanent: bool) -> Result<()> {
    let mut session = ctx.unlock()?;
    let item = find(&session, query, None)?;
    let (id, title) = (item.id.clone(), item.title.clone());
    if permanent {
        session.delete_item(&id)?;
        eprintln!("Deleted '{title}' permanently.");
    } else {
        session.trash_item(&id)?;
        eprintln!("Moved '{title}' to the trash. Restore with: 2secret restore {}", &id[..8]);
    }
    ctx.after_write(&mut session)
}

pub fn restore(ctx: &Ctx, query: &str) -> Result<()> {
    let mut session = ctx.unlock()?;
    let hits = session.list(&ItemFilter { trashed: true, query: query.to_string(), ..Default::default() });
    let id = match session.item(query) {
        Some(i) => i.id.clone(),
        None if hits.len() == 1 => hits[0].id.clone(),
        None if hits.is_empty() => bail!("no item '{query}' in the trash"),
        None => bail!("'{query}' matches several items in the trash; use the id"),
    };
    session.restore_item(&id)?;
    ctx.after_write(&mut session)?;
    eprintln!("Restored.");
    Ok(())
}

pub fn empty_trash(ctx: &Ctx) -> Result<()> {
    let mut session = ctx.unlock()?;
    let n = session.empty_trash(None)?;
    ctx.after_write(&mut session)?;
    eprintln!("Permanently deleted {n} items.");
    Ok(())
}

pub fn move_item(ctx: &Ctx, query: &str, to: &str) -> Result<()> {
    let mut session = ctx.unlock()?;
    let id = find(&session, query, None)?.id.clone();
    let target = session.find_vault(to)?;
    let new_id = session.move_item(&id, &target.id)?;
    ctx.after_write(&mut session)?;
    eprintln!("Moved to '{}' (new id {new_id}).", target.name);
    Ok(())
}

pub fn favorite(ctx: &Ctx, query: &str, on: bool) -> Result<()> {
    let mut session = ctx.unlock()?;
    let id = find(&session, query, None)?.id.clone();
    session.set_favorite(&id, on)?;
    ctx.after_write(&mut session)
}

pub fn history(ctx: &Ctx, query: &str) -> Result<()> {
    let session = ctx.unlock()?;
    let item = find(&session, query, None)?;
    if ctx.json {
        print_json(&item.password_history);
        return Ok(());
    }
    let rows: Vec<Vec<String>> =
        item.password_history.iter().map(|h| vec![format_timestamp(h.changed_at), h.value.clone()]).collect();
    table(&["replaced on", "password"], &rows);
    Ok(())
}

pub fn totp(ctx: &Ctx, query: &str) -> Result<()> {
    let session = ctx.unlock()?;
    let item = find(&session, query, None)?;
    let secret = item.totp_secret().ok_or_else(|| anyhow!("'{}' has no one-time password", item.title))?;
    let t = Totp::parse(secret)?;
    let (code, left) = t.now();
    if ctx.json {
        print_json(&json!({"code": code, "expires_in": left}));
    } else {
        println!("{code}");
        eprintln!("valid for {left} more seconds");
    }
    Ok(())
}

pub fn copy(ctx: &Ctx, query: &str, field: &str, clear_after: u64) -> Result<()> {
    let session = ctx.unlock()?;
    let item = find(&session, query, None)?;
    let reference =
        twosecret_core::secret_ref::SecretRef { vault: None, item: item.id.clone(), field: field.to_string() };
    let value = reference.resolve(&session)?;
    crate::clipboard::copy(&value, clear_after)?;
    eprintln!("Copied {field} of '{}'. The clipboard is cleared in {clear_after} seconds.", item.title);
    Ok(())
}

fn mime_for(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase().as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "txt" | "md" => "text/plain",
        "json" => "application/json",
        "pem" | "key" | "pub" => "application/x-pem-file",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

pub fn attach(ctx: &Ctx, query: &str, file: &Path) -> Result<()> {
    let mut session = ctx.unlock()?;
    let mut item = find(&session, query, None)?.clone();
    let bytes = std::fs::read(file)?;
    let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("attachment").to_string();
    item.attachments.push(Attachment::new(&name, mime_for(file), &bytes)?);
    session.update_item(item)?;
    ctx.after_write(&mut session)?;
    eprintln!("Attached {name}.");
    Ok(())
}

pub fn save_attachment(ctx: &Ctx, query: &str, name: &str, output: Option<PathBuf>) -> Result<()> {
    let session = ctx.unlock()?;
    let item = find(&session, query, None)?;
    let att = item
        .attachments
        .iter()
        .find(|a| a.name == name || a.id == name)
        .ok_or_else(|| anyhow!("no attachment '{name}'"))?;
    let out = output.unwrap_or_else(|| PathBuf::from(&att.name));
    if out.exists() {
        bail!("{} already exists", out.display());
    }
    std::fs::write(&out, att.bytes()?)?;
    eprintln!("Saved {}.", out.display());
    Ok(())
}
