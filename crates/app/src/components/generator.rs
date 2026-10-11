//! Password generator page.

use dioxus::prelude::*;
use twosecret_core::generator::{GeneratorKind, GeneratorOptions};
use twosecret_core::strength::StrengthLevel;

use crate::components::widgets::*;
use crate::i18n::t;
use crate::icons::Icon;
use crate::state::*;

fn update(f: impl FnOnce(&mut GeneratorOptions)) {
    f(&mut PREFS.write().generator);
    save_prefs();
}

#[component]
pub fn GeneratorPage() -> Element {
    let mut counter = use_signal(|| 0u32);
    let mut history = use_signal(Vec::<String>::new);
    let opts = PREFS.read().generator.clone();
    let value = use_memo(move || {
        counter();
        PREFS.read().generator.generate()
    });
    let bits = opts.entropy_bits();
    let level = match bits {
        b if b < 40.0 => StrengthLevel::Weak,
        b if b < 60.0 => StrengthLevel::Fair,
        b if b < 80.0 => StrengthLevel::Good,
        _ => StrengthLevel::Fantastic,
    };
    let kind = opts.kind;

    rsx! {
        div { class: "toolbar",
            button { class: "icon-btn mobile-only", onclick: move |_| *PANE.write() = Pane::Nav, Icon { name: "menu" } }
            span { class: "grow", style: "font-weight:600;font-size:16px", {t("nav.generator")} }
        }
        div { class: "detail-scroll",
            div { class: "detail-inner",
                div { class: "center", style: "margin-bottom:16px",
                    div { class: "segmented",
                        for (k , label) in [(GeneratorKind::Random, t("gen.random")), (GeneratorKind::Memorable, t("gen.memorable")), (GeneratorKind::Pin, t("gen.pin"))] {
                            button { key: "{label}", class: if k == kind { "on" } else { "" }, onclick: move |_| update(|o| o.kind = k), "{label}" }
                        }
                    }
                }
                div { class: "gen-output", ColoredPassword { value: value() } }
                div { class: "row", style: "justify-content:center;margin:14px 0 6px",
                    button { class: "btn primary",
                        onclick: move |_| {
                            let v = value();
                            history.with_mut(|h| { h.insert(0, v.clone()); h.truncate(8); });
                            copy(v, t("field.password"));
                        },
                        Icon { name: "copy", size: 16 }
                        {t("gen.copy")}
                    }
                    button { class: "btn", onclick: move |_| counter += 1,
                        Icon { name: "refresh", size: 16 }
                        {t("gen.regenerate")}
                    }
                }
                div { class: "center small muted", style: "margin-bottom:20px",
                    "{level_label(level)} · {bits:.0} bits"
                }
                div { class: "section",
                    div { class: "section-body", style: "padding-top:14px",
                        match kind {
                            GeneratorKind::Random => rsx! {
                                label { class: "label", "{t(\"gen.length\")}: {opts.length}" }
                                input { r#type: "range", min: "8", max: "64", value: "{opts.length}",
                                    oninput: move |e| { if let Ok(n) = e.value().parse() { update(|o| o.length = n); } } }
                                div { class: "col", style: "margin-top:12px",
                                    Toggle { label: t("gen.uppercase"), on: opts.uppercase, set: move |v| update(|o| o.uppercase = v) }
                                    Toggle { label: t("gen.lowercase"), on: opts.lowercase, set: move |v| update(|o| o.lowercase = v) }
                                    Toggle { label: t("gen.digits"), on: opts.digits, set: move |v| update(|o| o.digits = v) }
                                    Toggle { label: t("gen.symbols"), on: opts.symbols, set: move |v| update(|o| o.symbols = v) }
                                    Toggle { label: t("gen.ambiguous"), on: opts.avoid_ambiguous, set: move |v| update(|o| o.avoid_ambiguous = v) }
                                }
                            },
                            GeneratorKind::Memorable => rsx! {
                                label { class: "label", "{t(\"gen.words\")}: {opts.words}" }
                                input { r#type: "range", min: "3", max: "12", value: "{opts.words}",
                                    oninput: move |e| { if let Ok(n) = e.value().parse() { update(|o| o.words = n); } } }
                                div { class: "row", style: "margin:12px 0",
                                    label { class: "label", style: "margin:0", {t("gen.separator")} }
                                    select { class: "input", style: "width:auto",
                                        onchange: move |e| update(|o| o.separator = if e.value() == "space" { " ".into() } else { e.value() }),
                                        for (v , l) in [("-", "-"), (".", "."), ("_", "_"), (",", ","), ("space", "␣")] {
                                            option { key: "{v}", value: "{v}", selected: opts.separator == v || (v == "space" && opts.separator == " "), "{l}" }
                                        }
                                    }
                                }
                                div { class: "col",
                                    Toggle { label: t("gen.capitalize"), on: opts.capitalize, set: move |v| update(|o| o.capitalize = v) }
                                    Toggle { label: t("gen.number"), on: opts.include_number, set: move |v| update(|o| o.include_number = v) }
                                }
                            },
                            GeneratorKind::Pin => rsx! {
                                label { class: "label", "{t(\"gen.length\")}: {opts.pin_length}" }
                                input { r#type: "range", min: "4", max: "12", value: "{opts.pin_length}",
                                    oninput: move |e| { if let Ok(n) = e.value().parse() { update(|o| o.pin_length = n); } } }
                            },
                        }
                    }
                }
                if !history().is_empty() {
                    div { class: "section",
                        div { class: "section-title", {t("gen.history")} }
                        div { class: "section-body",
                            for (i , h) in history().into_iter().enumerate() {
                                div { class: "history-row", key: "{i}",
                                    ColoredPassword { value: h.clone() }
                                    button { class: "icon-btn", onclick: move |_| copy(h.clone(), t("field.password")), Icon { name: "copy", size: 14 } }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub fn Toggle(label: String, on: bool, set: EventHandler<bool>) -> Element {
    rsx! {
        label { class: "checkbox",
            input { r#type: "checkbox", checked: on, onchange: move |e| set.call(e.checked()) }
            span { "{label}" }
        }
    }
}
