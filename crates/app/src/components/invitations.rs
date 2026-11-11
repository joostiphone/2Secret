//! Vaults others shared with this account wait as invitations until it
//! accepts them (`Session::invitations`): a key sealed to our public key can
//! come from anyone, the server too. The banner on Home says whose vault it
//! is, with the fingerprint of their keys to compare with them.

use dioxus::prelude::*;
use twosecret_core::crypto::AccountPublicKeys;
use twosecret_core::session::Invitation;

use crate::i18n::{role_name, t};
use crate::icons::Icon;
use crate::state::*;

#[component]
pub fn InvitationBanner() -> Element {
    let invitations = SESSION.read().as_ref().map(|s| s.invitations()).unwrap_or_default();
    rsx! {
        for invitation in invitations {
            InvitationCard { key: "{invitation.vault_id}", invitation }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Answer {
    Accept,
    Decline,
}

fn answer(answer: Answer, vault_id: String) {
    let Some(mut session) = session_copy() else { return };
    spawn(async move {
        busy(t("busy.working"));
        let result = match answer {
            Answer::Accept => twosecret_client::accept_invitation(&mut session, &vault_id).await.map(|_| ()),
            Answer::Decline => twosecret_client::decline_invitation(&mut session, &vault_id).await,
        };
        unbusy();
        match result {
            Ok(()) => {
                install_session(session);
                toast(match answer {
                    Answer::Accept => t("invite.accepted"),
                    Answer::Decline => t("invite.declined"),
                });
            }
            Err(e) => report_error(&e, |m| toast_err(&m)),
        }
    });
}

#[component]
fn InvitationCard(invitation: Invitation) -> Element {
    // Who shares it comes from the server's member list.
    let vault_id = invitation.vault_id.clone();
    let owner = use_resource(move || {
        let vault_id = vault_id.clone();
        async move {
            let session = session_copy()?;
            twosecret_client::invitation_owner(&session, &vault_id).await.ok().flatten()
        }
    });
    let (who, fingerprint) = match &*owner.read() {
        Some(Some(m)) => (
            format!("{} ({})", m.name, m.email),
            AccountPublicKeys::from_b64(&m.public_key, m.pq_public_key.as_deref())
                .map(|k| k.fingerprint())
                .unwrap_or_default(),
        ),
        _ => (t("invite.someone").to_string(), String::new()),
    };
    let name = if invitation.opens { invitation.name.clone() } else { t("invite.unreadable").to_string() };
    let title = t("invite.title").replace("{name}", &who).replace("{vault}", &name);
    let role = role_name(invitation.role);
    let accept_id = invitation.vault_id.clone();
    let decline_id = invitation.vault_id.clone();
    rsx! {
        div { class: "banner",
            Icon { name: "users", size: 18 }
            div { class: "grow",
                div { class: "t", "{title}" }
                div { class: "d",
                    {t("invite.desc").replace("{role}", role)}
                    if !fingerprint.is_empty() {
                        " "
                        span { class: "mono", style: "white-space:nowrap", "{fingerprint}" }
                    }
                }
            }
            div { class: "row",
                button { class: "btn small", onclick: move |_| answer(Answer::Decline, decline_id.clone()), {t("invite.decline")} }
                if invitation.opens {
                    button { class: "btn small primary", onclick: move |_| answer(Answer::Accept, accept_id.clone()), {t("invite.accept")} }
                }
            }
        }
    }
}
