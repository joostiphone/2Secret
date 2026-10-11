//! Watchtower: security dashboard.

use dioxus::prelude::*;
use twosecret_core::watchtower::{analyze, IssueKind};

use crate::i18n::{issue_desc, issue_title, t};
use crate::icons::{either, Icon};
use crate::state::*;

#[component]
pub fn WatchtowerPage(kind: Option<IssueKind>) -> Element {
    let mut checking = use_signal(|| false);
    let breaches = BREACHES.read().clone();
    let session = SESSION.read();
    let Some(s) = session.as_ref() else { return rsx! {} };
    let report = analyze(s.all_items(), &breaches.clone().unwrap_or_default(), None);
    drop(session);
    let score = report.score;
    let rating = match report.rating() {
        "fantastic" => t("wt.fantastic"),
        "very_good" => t("wt.very_good"),
        "good" => t("wt.good"),
        "fair" => t("wt.fair"),
        _ => t("wt.poor"),
    };
    let color = match score {
        900.. => "#1c7ed6",
        750..=899 => "#37b24d",
        600..=749 => "#f59f00",
        _ => "#e03131",
    };
    let circumference = 2.0 * std::f64::consts::PI * 52.0;
    let dash = circumference * score as f64 / 1000.0;

    let check_breaches = move |_| {
        checking.set(true);
        spawn(async move {
            let prepared = SESSION.peek().as_ref().map(twosecret_client::breach_check_prepare);
            if let Some(entries) = prepared {
                match twosecret_client::breach_check_hashes(entries).await {
                    Ok(map) => {
                        let n = map.len();
                        *BREACHES.write() = Some(map);
                        toast(&format!("{}: {n}", t("wt.breach_done")));
                    }
                    Err(e) => toast_err(&client_error(&e)),
                }
            }
            checking.set(false);
        });
    };

    rsx! {
        div { class: "toolbar",
            button { class: "icon-btn mobile-only", onclick: move |_| *PANE.write() = Pane::Nav, Icon { name: "menu" } }
            if kind.is_some() {
                button { class: "btn ghost small", onclick: move |_| *NAV.write() = Nav::Watchtower(None),
                    Icon { name: "chevron-left", size: 16 }
                    {t("nav.watchtower")}
                }
            } else {
                span { class: "grow", style: "font-weight:600;font-size:16px", {t("nav.watchtower")} }
            }
        }
        div { class: "detail-scroll",
            div { class: "detail-inner",
                match kind {
                    None => rsx! {
                        div { class: "section",
                            div { class: "score",
                                svg { class: "score-ring", view_box: "0 0 120 120",
                                    circle { cx: "60", cy: "60", r: "52", fill: "none", stroke: "var(--border)", stroke_width: "10" }
                                    circle { cx: "60", cy: "60", r: "52", fill: "none", stroke: "{color}", stroke_width: "10", stroke_linecap: "round",
                                        stroke_dasharray: "{dash} {circumference}", transform: "rotate(-90 60 60)" }
                                    text { x: "60", y: "66", text_anchor: "middle", font_size: "26", font_weight: "800", fill: "currentColor", "{score}" }
                                }
                                div {
                                    div { class: "score-num", style: "color:{color}", "{rating}" }
                                    div { class: "muted", "{report.items_checked} {t(\"wt.items_checked\")}" }
                                    div { class: "muted small", style: "margin-top:6px;max-width:420px", {t("wt.explain")} }
                                }
                            }
                        }
                        div { class: "section",
                            for k in IssueKind::ALL {
                                {
                                    let n = report.count(k);
                                    rsx! {
                                        div { class: "issue-card", key: "{k.id()}", onclick: move |_| *NAV.write() = Nav::Watchtower(Some(k)),
                                            Icon { name: either(n > 0, "alert", "check"), size: 20 }
                                            div { class: "grow",
                                                div { style: "font-weight:600", {issue_title(k)} }
                                                div { class: "small muted", {issue_desc(k)} }
                                            }
                                            div { class: if n > 0 { "issue-count danger-text" } else { "issue-count ok-text" }, "{n}" }
                                            Icon { name: "chevron-right", size: 16 }
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "section",
                            div { class: "settings-row",
                                div { class: "k",
                                    div { class: "t", {t("wt.breach_title")} }
                                    div { class: "d", {t("wt.breach_desc")} }
                                }
                                button { class: "btn", disabled: checking(), onclick: check_breaches,
                                    if checking() { div { class: "spinner", style: "width:16px;height:16px;border-width:2px" } } else { Icon { name: "shield", size: 16 } }
                                    if breaches.is_some() { {t("wt.breach_again")} } else { {t("wt.breach_check")} }
                                }
                            }
                        }
                    },
                    Some(k) => rsx! {
                        h2 { style: "margin-top:0", {issue_title(k)} }
                        p { class: "muted", {issue_desc(k)} }
                        if report.count(k) == 0 {
                            div { class: "empty", Icon { name: "check", size: 40 } p { {t("wt.none")} } }
                        } else {
                            div { class: "section",
                                for issue in report.of_kind(k).into_iter().cloned() {
                                    div { class: "issue-card", key: "{issue.item_id}",
                                        onclick: move |_| {
                                            *NAV.write() = Nav::All;
                                            clear_search();
                                            *SELECTED.write() = Some(issue.item_id.clone());
                                            *PANE.write() = Pane::Detail;
                                        },
                                        div { class: "grow",
                                            div { style: "font-weight:600", "{issue.title}" }
                                            div { class: "small muted", "{issue.detail}" }
                                        }
                                        Icon { name: "chevron-right", size: 16 }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }
}
