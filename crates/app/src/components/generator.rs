//! Password generator page.

use dioxus::prelude::*;
use twosecret_core::generator::{GeneratorKind, GeneratorOptions, MAX_LENGTH, MAX_WORDS, MIN_LENGTH, MIN_WORDS};
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
                div { class: "center small muted", style: "margin-bottom:20px", {strength(&opts)} }
                div { class: "section",
                    div { class: "section-body", style: "padding-top:14px",
                        GeneratorControls { opts: opts.clone(), set: move |o| { PREFS.write().generator = o; save_prefs(); }, kinds: false }
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

/// "Good · 105 bits": how strong secrets made with these options are.
pub fn strength(opts: &GeneratorOptions) -> String {
    let bits = opts.entropy_bits();
    let level = match bits {
        b if b < 40.0 => StrengthLevel::Weak,
        b if b < 60.0 => StrengthLevel::Fair,
        b if b < 80.0 => StrengthLevel::Good,
        _ => StrengthLevel::Fantastic,
    };
    format!("{} · {bits:.0} bits", level_label(level))
}

/// The generator's options: length, character sets and so on, for the
/// generator page and for one password in the item editor. `kinds` adds the
/// choice between random, memorable and PIN.
#[component]
pub fn GeneratorControls(
    opts: ReadSignal<GeneratorOptions>,
    set: EventHandler<GeneratorOptions>,
    kinds: bool,
) -> Element {
    let change = move |f: &dyn Fn(&mut GeneratorOptions)| {
        let mut o = opts();
        f(&mut o);
        set.call(o);
    };
    let opts = opts();
    let kind = opts.kind;
    rsx! {
        if kinds {
            div { class: "segmented", style: "margin-bottom:12px",
                for (k , label) in [(GeneratorKind::Random, t("gen.random")), (GeneratorKind::Memorable, t("gen.memorable")), (GeneratorKind::Pin, t("gen.pin"))] {
                    button { key: "{label}", r#type: "button", class: if k == kind { "on" } else { "" }, onclick: move |_| change(&|o| o.kind = k), "{label}" }
                }
            }
        }
        match kind {
            GeneratorKind::Random => rsx! {
                LengthInput { label: t("gen.length"), value: opts.length, min: MIN_LENGTH, max: 64, limit: MAX_LENGTH,
                    set: move |n| change(&|o| o.length = n) }
                div { class: "col", style: "margin-top:12px",
                    Toggle { label: t("gen.uppercase"), on: opts.uppercase, set: move |v| change(&|o| o.uppercase = v) }
                    Toggle { label: t("gen.lowercase"), on: opts.lowercase, set: move |v| change(&|o| o.lowercase = v) }
                    Toggle { label: t("gen.digits"), on: opts.digits, set: move |v| change(&|o| o.digits = v) }
                    Toggle { label: t("gen.symbols"), on: opts.symbols, set: move |v| change(&|o| o.symbols = v) }
                    Toggle { label: t("gen.ambiguous"), on: opts.avoid_ambiguous, set: move |v| change(&|o| o.avoid_ambiguous = v) }
                }
            },
            GeneratorKind::Memorable => rsx! {
                LengthInput { label: t("gen.words"), value: opts.words, min: MIN_WORDS, max: 12, limit: MAX_WORDS,
                    set: move |n| change(&|o| o.words = n) }
                div { class: "row", style: "margin:12px 0",
                    label { class: "label", style: "margin:0", {t("gen.separator")} }
                    select { class: "input", style: "width:auto",
                        onchange: move |e| change(&|o| o.separator = if e.value() == "space" { " ".into() } else { e.value() }),
                        for (v , l) in [("-", "-"), (".", "."), ("_", "_"), (",", ","), ("space", "␣")] {
                            option { key: "{v}", value: "{v}", selected: opts.separator == v || (v == "space" && opts.separator == " "), "{l}" }
                        }
                    }
                }
                div { class: "col",
                    Toggle { label: t("gen.capitalize"), on: opts.capitalize, set: move |v| change(&|o| o.capitalize = v) }
                    Toggle { label: t("gen.number"), on: opts.include_number, set: move |v| change(&|o| o.include_number = v) }
                }
            },
            GeneratorKind::Pin => rsx! {
                LengthInput { label: t("gen.length"), value: opts.pin_length, min: MIN_LENGTH, max: 12, limit: 32,
                    set: move |n| change(&|o| o.pin_length = n) }
            },
        }
    }
}

/// A slider for the usual range and a number field for the rest (sites that
/// want exactly 8 or allow 100 characters).
#[component]
fn LengthInput(label: String, value: usize, min: usize, max: usize, limit: usize, set: EventHandler<usize>) -> Element {
    let parse = move |text: String| text.trim().parse::<usize>().ok().map(|n| n.clamp(min, limit));
    rsx! {
        div { class: "row", style: "gap:10px",
            label { class: "label", style: "margin:0", "{label}" }
            input { r#type: "range", class: "grow", min: "{min}", max: "{max}", value: "{value.min(max)}",
                oninput: move |e| { if let Some(n) = parse(e.value()) { set.call(n); } } }
            input { r#type: "number", class: "input", style: "width:72px", min: "{min}", max: "{limit}", value: "{value}",
                onchange: move |e| { if let Some(n) = parse(e.value()) { set.call(n); } } }
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
