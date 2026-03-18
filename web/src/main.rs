#[cfg(target_arch = "wasm32")]
use dioxus::prelude::*;
#[cfg(target_arch = "wasm32")]
use gloo_timers::future::TimeoutFuture;
#[cfg(target_arch = "wasm32")]
use ygg_vanity::wasm::{WasmMatch, WasmProgress, WasmVanityEngine};

#[cfg(target_arch = "wasm32")]
const DEFAULT_TEMPLATE: &str = "200:?:?:?:dead:beef:?:?";
#[cfg(target_arch = "wasm32")]
const DEFAULT_MAX_FOUND: &str = "1";
#[cfg(target_arch = "wasm32")]
const DEFAULT_BATCH_SIZE: &str = "4096";
#[cfg(target_arch = "wasm32")]
const STYLES: &str = include_str!("../assets/main.css");

#[cfg(target_arch = "wasm32")]
fn main() {
    dioxus::launch(App);
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!(
        "ygg-vanity-web — это браузерное wasm-приложение, его нельзя запускать через `cargo run` на нативном target."
    );
    eprintln!("Используй одну из этих команд:");
    eprintln!("  cd web && dx serve --platform web");
    eprintln!("  cargo check -p ygg-vanity-web --target wasm32-unknown-unknown");
    std::process::exit(1);
}

#[cfg(target_arch = "wasm32")]
#[component]
fn App() -> Element {
    let mut template = use_signal(|| DEFAULT_TEMPLATE.to_string());
    let mut max_found = use_signal(|| DEFAULT_MAX_FOUND.to_string());
    let mut batch_size = use_signal(|| DEFAULT_BATCH_SIZE.to_string());
    let mut running = use_signal(|| false);
    let mut error = use_signal(|| Option::<String>::None);
    let mut progress = use_signal(WasmProgress::default);
    let mut results = use_signal(Vec::<WasmMatch>::new);

    let start_generation = {
        move |_| {
            if running() {
                return;
            }

            let template_value = template();
            let max_found_value = match parse_positive_usize(&max_found(), "максимум результатов")
            {
                Ok(value) => value,
                Err(message) => {
                    error.set(Some(message));
                    return;
                }
            };
            let batch_size_value = match parse_positive_usize(&batch_size(), "размер батча")
            {
                Ok(value) => value,
                Err(message) => {
                    error.set(Some(message));
                    return;
                }
            };

            results.set(Vec::new());
            progress.set(WasmProgress::default());
            error.set(None);
            running.set(true);

            spawn(async move {
                let mut engine = match WasmVanityEngine::from_template(&template_value) {
                    Ok(engine) => engine,
                    Err(err) => {
                        error.set(Some(err.to_string()));
                        running.set(false);
                        return;
                    }
                };

                loop {
                    if !running() {
                        break;
                    }

                    let remaining = max_found_value.saturating_sub(results().len());
                    if remaining == 0 {
                        running.set(false);
                        break;
                    }

                    let batch = engine.step(batch_size_value, remaining);
                    if !batch.is_empty() {
                        let mut next_results = results();
                        next_results.extend(batch);
                        results.set(next_results);
                    }

                    progress.set(engine.progress());

                    if results().len() >= max_found_value {
                        running.set(false);
                        break;
                    }

                    TimeoutFuture::new(0).await;
                }

                progress.set(engine.progress());
            });
        }
    };

    rsx! {
        style { {STYLES} }
        main { class: "page",
            section { class: "shell",
                header { class: "hero",
                    p { class: "eyebrow", "wasm / dioxus" }
                    h1 { "Norn" }
                    p { class: "lede",
                        "Браузерный vanity generator без внешних программ.\nФормат матчинга только template: "
                        code { "200:?:?:?:dead:beef:?:?" }
                    }
                }

                section { class: "panel controls",
                    div { class: "field",
                        label { "Шаблон" }
                        input {
                            class: "input mono",
                            value: "{template}",
                            placeholder: "200:?:?:?:dead:beef:?:?",
                            oninput: move |event| template.set(event.value())
                        }
                        p { class: "hint", "Используй ровно 8 хекстет-групп." }
                        p { class: "hint", "Первый хекстет служит только как удобный префикс и не участвует в матче." }
                        p { class: "hint", code { "?" } " означает любую группу целиком." }
                    }

                    div { class: "grid",
                        div { class: "field",
                            label { "Максимум найденных адресов за раз" }
                            input {
                                class: "input mono",
                                r#type: "number",
                                min: "1",
                                step: "1",
                                value: "{max_found}",
                                oninput: move |event| max_found.set(event.value())
                            }
                        }
                        div { class: "field",
                            label { "Размер батча" }
                            input {
                                class: "input mono",
                                r#type: "number",
                                min: "1",
                                step: "1",
                                value: "{batch_size}",
                                oninput: move |event| batch_size.set(event.value())
                            }
                        }
                    }

                    div { class: "actions",
                        button {
                            class: "button primary",
                            disabled: running(),
                            onclick: start_generation,
                            if running() { "В процессе..." } else { "Начать" }
                        }
                        button {
                            class: "button ghost",
                            disabled: !running(),
                            onclick: move |_| running.set(false),
                            "Стоп"
                        }
                    }

                    if let Some(message) = error() {
                        p { class: "error", "{message}" }
                    }
                }

                section { class: "panel stats",
                    div { class: "stat",
                        span { class: "label", "Ключей" }
                        strong { class: "value mono", "{progress().total_keys}" }
                    }
                    div { class: "stat",
                        span { class: "label", "Скорость" }
                        strong { class: "value mono", "{format_number(progress().keys_per_sec)} / с" }
                    }
                    div { class: "stat",
                        span { class: "label", "Найдено" }
                        strong { class: "value mono", "{progress().found}" }
                    }
                    div { class: "stat",
                        span { class: "label", "Время" }
                        strong { class: "value mono", "{format_elapsed(progress().elapsed_secs)}" }
                    }
                    div { class: "stat",
                        span { class: "label", "Ожидание" }
                        strong { class: "value mono", "{format_number(progress().expected_attempts)}" }
                        p { class: "hint", "Грубая оценка числа попыток до первого совпадения." }
                    }
                    div { class: "stat",
                        span { class: "label", "Невезение" }
                        strong { class: "value mono", "{format_percent(progress().unluckiness_pct)}" }
                        p { class: "hint", "Шуточный счётчик: насколько странно, что при 0 находок всё ещё пусто." }
                    }
                }

                section { class: "panel results",
                    div { class: "results-head",
                        h2 { "Совпадения" }
                        p { class: "hint", "Результаты появляются по мере нахождения и уже готовы к копированию." }
                    }

                    if results().is_empty() {
                        div { class: "empty",
                            p { "Пока пусто. Запусти поиск или попробуй менее редкий шаблон." }
                        }
                    } else {
                        for item in results().iter() {
                            article { class: "match-card",
                                div { class: "match-row",
                                    span { class: "chip", "{item.address}" }
                                }
                                label { "Приватный ключ" }
                                textarea {
                                    class: "output mono",
                                    readonly: true,
                                    rows: "3",
                                    value: "{item.private_key}",
                                }
                                label { "Публичный ключ" }
                                textarea {
                                    class: "output mono",
                                    readonly: true,
                                    rows: "2",
                                    value: "{item.public_key}",
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn parse_positive_usize(input: &str, field: &str) -> Result<usize, String> {
    let value = input
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("Некорректное поле «{field}»: {input}"))?;

    if value == 0 {
        return Err(format!("Поле «{field}» должно быть больше нуля"));
    }

    Ok(value)
}

#[cfg(target_arch = "wasm32")]
fn format_number(value: f64) -> String {
    if value >= 1_000_000.0 {
        format!("{:.2}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1}K", value / 1_000.0)
    } else {
        format!("{value:.0}")
    }
}

#[cfg(target_arch = "wasm32")]
fn format_elapsed(value: f64) -> String {
    format!("{value:.1} с")
}

#[cfg(target_arch = "wasm32")]
fn format_percent(value: f64) -> String {
    format!("{value:.2}%")
}
