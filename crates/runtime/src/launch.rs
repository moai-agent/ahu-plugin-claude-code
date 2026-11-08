use serde::Deserialize;
use serde_json::{Value, json};
const PROMPT: &str = "<prompt: see prompt.txt>";
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Interactive,
    Headless,
    Direct,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Permissions {
    Prompt,
    AcceptEdits,
    Auto,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    mode: Mode,
    model: String,
    permissions: Permissions,
    work_mode: bool,
    session: Option<String>,
    native_version: String,
    timeout_seconds: u64,
    cwd: String,
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    broker_dir: Option<String>,
    native_profile: Option<Value>,
    native_controls: Vec<String>,
}
fn identity(value: &str, limit: usize, alphabet: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || alphabet.contains(&b))
}
pub(super) fn plan(harness: &str, params: Value) -> Result<Value, ()> {
    let r: Request = serde_json::from_value(params).map_err(|_| ())?;
    if !identity(&r.model, 256, b"-_.:/+")
        || !(1..=604800).contains(&r.timeout_seconds)
        || r.session.as_ref().is_some_and(|s| !identity(s, 128, b"-_"))
        || !std::path::Path::new(&r.cwd).is_absolute()
        || r.cwd.contains('\0')
        || r.work_mode && r.permissions != Permissions::Auto
        || r.mode != Mode::Headless && (r.session.is_some() || r.work_mode)
        || r.native_controls.len() > 128
    {
        return Err(());
    }
    // Core enforces explicit project pins. Unpinned native versions float;
    // version-specific controls still require their inspected admission evidence.
    let version = ahu_harness_native::version_token(&r.native_version).ok_or(())?;
    let _standalone = version.starts_with("2.");

    let program = match harness {
        "claude-code" => "claude",

        other => other,
    };
    let mut args: Vec<String> = Vec::new();
    let mut add = |values: &[&str]| args.extend(values.iter().map(|s| (*s).to_owned()));
    if r.mode == Mode::Direct && r.permissions == Permissions::Auto {
        match harness {
            "claude-code" => add(&["--model", &r.model, "--dangerously-skip-permissions"]),

            // The reviewed mini CLI has no unattended permission override.
            _ => return Err(()),
        }
        return Ok(
            json!({"program":program,"args":args,"prompt_arg":null,"native_eval_otlp":harness != "kiro"}),
        );
    }
    if r.mode == Mode::Headless {
        match harness {
            "claude-code" => {
                add(&[
                    "--print",
                    "--model",
                    &r.model,
                    "--output-format",
                    "stream-json",
                    "--verbose",
                    "--permission-prompts",
                    "none",
                ]);
                if !r.work_mode {
                    let id = format!(
                        "native.isolation.claude-{version}-nonmanaged-hooks-disabled-v1=flag"
                    );
                    if ["2.1.283", "2.1.288", "2.1.289", "2.1.302"].contains(&version) {
                        if !r.native_controls.contains(&id) {
                            return Err(());
                        }
                        add(&["--settings", "{\"disableAllHooks\":true}"]);
                    }
                    if let Some(profile) = &r.native_profile {
                        let values: Vec<String> =
                            serde_json::from_value(profile.get("args").ok_or(())?.clone())
                                .map_err(|_| ())?;
                        if values.len() > 64
                            || values.iter().any(|s| s.len() > 65536 || s.contains('\0'))
                        {
                            return Err(());
                        }
                        add(&values.iter().map(String::as_str).collect::<Vec<_>>());
                    } else {
                        add(&["--disallowedTools", "Agent,Task,TeamCreate,TeamDelete"]);
                    }
                }
                match r.permissions {
                    Permissions::Prompt => (),
                    Permissions::Auto => add(&["--permission-mode", "auto"]),
                    Permissions::AcceptEdits => add(&["--permission-mode", "acceptEdits"]),
                }
                if let Some(session) = &r.session {
                    add(&["--resume", session]);
                }
                add(&["--"]);
            }

            _ => return Err(()),
        }
    } else {
        match harness {
            "claude-code" => {
                add(&["--model", &r.model]);
                match r.permissions {
                    Permissions::Prompt => (),
                    Permissions::AcceptEdits => add(&["--permission-mode", "acceptEdits"]),
                    Permissions::Auto => add(&[
                        "--permission-mode",
                        "auto",
                        "--settings",
                        "{\"enabledMcpjsonServers\":[\"ahu\"]}",
                    ]),
                }
                if r.mode == Mode::Interactive {
                    add(&["--"]);
                }
            }

            _ => return Err(()),
        }
    }
    let prompt_arg = if r.mode == Mode::Direct {
        None
    } else {
        let i = args.len();
        args.push(PROMPT.into());
        Some(i)
    };
    Ok(
        json!({"program":program,"args":args,"prompt_arg":prompt_arg,"native_eval_otlp":harness != "kiro"}),
    )
}
