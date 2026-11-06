//! Watchtower: security dashboard.

use dioxus::prelude::*;
use twosecret_core::watchtower::{analyze, IssueKind, Report};

use crate::i18n::{issue_desc, issue_title, t};
use crate::icons::{either, Icon};
use crate::state::*;

/// The bands of the score: where each starts, its name, and the two
/// colours of its gradient (light to deep).
const BANDS: [(u32, &str, &str, &str); 5] = [
    (0, "wt.poor", "#ff8787", "#e03131"),
    (400, "wt.fair", "#ffa94d", "#e8590c"),
    (600, "wt.good", "#ffd43b", "#f08c00"),
    (750, "wt.very_good", "#69db7c", "#2b8a3e"),
    (900, "wt.fantastic", "#3bc9db", "#4c6ef5"),
];

fn band(score: u32) -> (u32, &'static str, &'static str, &'static str) {
    BANDS.iter().rev().find(|b| score >= b.0).copied().unwrap_or(BANDS[0])
}

/// The security score in words and its colour.
pub fn rating(report: &Report) -> (&'static str, &'static str) {
    let (_, words, _, color) = band(report.score);
    (t(words), color)
}

/// `#rrggbb` to its three channels.
fn rgb(hex: &str) -> [f64; 3] {
    let v = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0);
    [((v >> 16) & 255) as f64, ((v >> 8) & 255) as f64, (v & 255) as f64]
}

/// The colour a fraction `f` of the way from `a` to `b`.
fn mix(a: &str, b: &str, f: f64) -> String {
    let (a, b) = (rgb(a), rgb(b));
    let c: Vec<u8> = (0..3).map(|i| (a[i] + (b[i] - a[i]) * f).round() as u8).collect();
    format!("#{:02x}{:02x}{:02x}", c[0], c[1], c[2])
}

/// The score as a ring: an arc whose colour sweeps from light to deep as it
/// fills up, with a soft glow, a knob at its end and the score in the
/// middle. `small` for the dashboard.
#[component]
pub fn ScoreRing(score: u32, #[props(default)] small: bool) -> Element {
    let score = score.min(1000);
    let (_, _, light, deep) = band(score);
    let (r, width, id) = if small { (54.0, 13.0, "ring-s") } else { (56.0, 12.0, "ring-l") };
    let circumference = 2.0 * std::f64::consts::PI * r;
    let frac = score as f64 / 1000.0;
    let dash = circumference * frac;
    // The sweep: short pieces of the arc, each a shade deeper.
    const PIECES: f64 = 90.0;
    let piece = circumference / PIECES;
    let count = (PIECES * frac).ceil() as usize;
    let mut sweep = String::new();
    for i in 0..count {
        let color = mix(light, deep, if count > 1 { i as f64 / (count - 1) as f64 } else { 1.0 });
        sweep.push_str(&format!(
            r#"<circle cx="70" cy="70" r="{r}" fill="none" stroke="{color}" stroke-width="{width}" stroke-dasharray="{len:.3} {circumference:.3}" stroke-dashoffset="{off:.3}"/>"#,
            len = piece + 0.6,
            off = -(i as f64) * piece,
        ));
    }
    let degrees = 360.0 * frac;
    let knob = if score > 0 {
        format!(
            r##"<g class="ring-knob" style="transform: rotate({degrees:.2}deg)"><circle cx="70" cy="{y}" r="{kr}" fill="#fff" stroke="{deep}" stroke-width="{kw}"/></g>"##,
            y = 70.0 - r,
            kr = width / 2.0 + 1.5,
            kw = if small { 4 } else { 3 },
        )
    } else {
        String::new()
    };
    let label = if small {
        format!(r#"<text x="70" y="82" text-anchor="middle" class="ring-num small">{score}</text>"#)
    } else {
        format!(
            r#"<text x="70" y="76" text-anchor="middle" class="ring-num">{score}</text><text x="70" y="96" text-anchor="middle" class="ring-of">/ 1000</text>"#
        )
    };
    let svg = format!(
        r##"<svg viewBox="0 0 140 140" aria-hidden="true">
<defs>
  <radialGradient id="{id}-d"><stop offset="0" stop-color="{light}" stop-opacity=".24"/><stop offset="1" stop-color="{light}" stop-opacity="0"/></radialGradient>
  <filter id="{id}-b" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="5"/></filter>
  <mask id="{id}-m" maskUnits="userSpaceOnUse" x="0" y="0" width="140" height="140">
    <circle class="ring-arc" cx="70" cy="70" r="{r}" fill="none" stroke="#fff" stroke-width="{width}" stroke-linecap="round" stroke-dasharray="{dash:.2} {circumference:.2}" transform="rotate(-90 70 70)" style="--ring-dash: {dash:.2}"/>
  </mask>
</defs>
<circle cx="70" cy="70" r="{disc}" fill="url(#{id}-d)"/>
<circle cx="70" cy="70" r="{r}" fill="none" stroke="{deep}" stroke-opacity=".13" stroke-width="{width}"/>
<circle cx="70" cy="70" r="{r}" fill="none" stroke="currentColor" stroke-opacity=".18" stroke-width="1.2" stroke-dasharray="0.01 {tick:.3}" stroke-linecap="round" transform="rotate(-90 70 70)"/>
<g mask="url(#{id}-m)">
  <g class="ring-glow" filter="url(#{id}-b)" transform="rotate(-90 70 70)">{sweep}</g>
  <g transform="rotate(-90 70 70)">{sweep}</g>
  <circle cx="70" cy="{top}" r="{cap}" fill="{light}"/>
</g>
{knob}
{label}
</svg>"##,
        disc = r - width / 2.0 - 2.0,
        tick = circumference / 40.0,
        top = 70.0 - r,
        cap = width / 2.0,
    );
    rsx! {
        div { class: if small { "score-ring small" } else { "score-ring" }, dangerous_inner_html: "{svg}" }
    }
}

/// Where the score is among the bands, with their names.
#[component]
fn ScoreScale(score: u32) -> Element {
    let at = score.min(1000) as f64 / 10.0;
    let current = band(score).0;
    rsx! {
        div { class: "score-scale", aria_hidden: "true",
            div { class: "bar",
                for (i , (start , _ , light , deep)) in BANDS.iter().enumerate() {
                    {
                        let end = BANDS.get(i + 1).map_or(1000, |b| b.0);
                        let width = (end - start) as f64 / 10.0;
                        rsx! {
                            span { key: "{start}", class: if *start == current { "seg on" } else { "seg" },
                                style: "width:{width}%;background:linear-gradient(90deg,{light},{deep})" }
                        }
                    }
                }
                span { class: "marker", style: "left:{at}%" }
            }
            div { class: "labels",
                for (start , name , _ , _) in BANDS {
                    span { key: "{start}", class: if start == current { "on" } else { "" }, style: "left:{start as f64 / 10.0}%", {t(name)} }
                }
            }
        }
    }
}

#[component]
pub fn WatchtowerPage(kind: Option<IssueKind>) -> Element {
    let mut checking = use_signal(|| false);
    let breaches = BREACHES.read().clone();
    let session = SESSION.read();
    let Some(s) = session.as_ref() else { return rsx! {} };
    let report = analyze(s.all_items(), &breaches.clone().unwrap_or_default(), None);
    drop(session);
    let score = report.score;
    let (words, _) = rating(&report);
    let (_, _, light, deep) = band(score);

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
                        div { class: "section score-hero", style: "--band-light:{light};--band-deep:{deep}",
                            div { class: "score",
                                ScoreRing { score }
                                div { class: "score-text",
                                    div { class: "score-num", "{words}" }
                                    div { class: "muted", "{report.items_checked} {t(\"wt.items_checked\")}" }
                                    ScoreScale { score }
                                    div { class: "muted small explain", {t("wt.explain")} }
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
