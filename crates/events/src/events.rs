use crate::{identity, skills};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SkillInvocation {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    #[serde(default)]
    pub harness: Option<String>,
    #[serde(default)]
    pub observed_at: Option<String>,
    #[serde(default = "crate::SkillEvidence::unverified")]
    pub evidence: crate::SkillEvidence,
    #[serde(default = "crate::SkillEvidence::unverified")]
    pub execution: crate::SkillEvidence,
}

/// Independent maximum observations per field in this attempt's native stream.
/// Fields may come from different events; these are not additive call totals or
/// a coherent snapshot, and resumed/child streams may contain overlapping usage.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct TokenUsage {
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub cached: Option<u64>,
    #[serde(default)]
    pub cache_write: Option<u64>,
    #[serde(default)]
    pub reasoning: Option<u64>,
    pub total: Option<u64>,
}

/// USD amounts reported by the harness. These are estimates/engine values,
/// not provider billing records.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct ReportedCost {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl TokenUsage {
    fn observe(&mut self, event: &Value) {
        fn max_slot(slot: &mut Option<u64>, value: Option<u64>) {
            if let Some(value) = value {
                *slot = Some(slot.unwrap_or(0).max(value));
            }
        }
        for usage in [
            event.get("usage"),
            event.pointer("/part/usage"),
            event.pointer("/result/usage"),
            event.pointer("/response/usage"),
            event.pointer("/step_update/usage"),
            event.pointer("/result/result/usage"),
            event.pointer("/step_update/tool_info/usage"),
            event.get("tokens"),
            event.pointer("/part/tokens"),
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        {
            let number = |keys: &[&str]| {
                keys.iter()
                    .find_map(|key| usage.get(*key).and_then(Value::as_u64))
            };
            max_slot(&mut self.input, number(&["input_tokens", "prompt_tokens"]));
            max_slot(
                &mut self.output,
                number(&["output_tokens", "completion_tokens"]),
            );
            max_slot(
                &mut self.cached,
                number(&[
                    "cached_tokens",
                    "cache_read_input_tokens",
                    "cached_input_tokens",
                ])
                .or_else(|| {
                    usage
                        .get("cache")
                        .and_then(|cache| cache.get("read"))
                        .and_then(Value::as_u64)
                }),
            );
            max_slot(
                &mut self.cache_write,
                number(&["cache_write_input_tokens", "cache_creation_input_tokens"]).or_else(
                    || {
                        usage
                            .get("cache")
                            .and_then(|cache| cache.get("write"))
                            .and_then(Value::as_u64)
                    },
                ),
            );
            max_slot(
                &mut self.reasoning,
                number(&["reasoning_output_tokens", "thinking_tokens", "reasoning"]),
            );
            max_slot(&mut self.total, number(&["total_tokens"]));
        }
    }
}

impl ReportedCost {
    fn observe_claude_result(&mut self, event: &Value) {
        if event.get("type").and_then(Value::as_str) != Some("result") {
            return;
        }
        let Some(value) = Self::valid_amount(event.get("total_cost_usd")) else {
            return;
        };
        // Result totals are cumulative observations, including on resume. A
        // duplicate or older snapshot must not increase the reported amount.
        self.usd = Some(self.usd.map_or(value, |prior| prior.max(value)));
        self.source = Some("native_cumulative_usd".into());
    }

    fn valid_amount(value: Option<&Value>) -> Option<f64> {
        value
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite() && *value >= 0.0)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Events {
    pub session: Option<String>,
    pub terminal: bool,
    /// Set only when the terminal result came from somewhere other than the
    /// harness's own event stream, so a reader can tell the two apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_evidence: Option<String>,
    pub failed: bool,
    #[serde(skip_serializing)]
    pub summary: String,
    pub blockers: Vec<String>,
    pub unknown_events: u64,
    #[serde(default)]
    pub stderr_diagnostics: Vec<String>,
    #[serde(default)]
    pub stderr_unclassified_lines: u64,
    #[serde(default)]
    pub stderr_informational_lines: u64,
    #[serde(default)]
    pub usage: TokenUsage,
    #[serde(default)]
    pub trajectory: crate::trajectory::Observer,
    #[serde(default)]
    pub cost: ReportedCost,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(skip)]
    pub(crate) model_evidence: identity::ModelEvidence,
    #[serde(default)]
    pub skills: Vec<SkillInvocation>,
    #[serde(default)]
    pub skill_unknown_events: u64,
    #[serde(skip)]
    pub(crate) skill_calls: Vec<skills::Call>,

    #[serde(default = "crate::SkillEvidence::unverified")]
    pub skill_observation: crate::SkillEvidence,
    #[serde(default)]
    #[serde(skip_serializing)]
    pub native: crate::native::Observations,
    #[serde(skip)]
    pub(crate) native_event_count: usize,

    #[serde(skip)]
    pub(crate) cost_tracking_limited: bool,
}
impl Events {
    pub(crate) fn observe_stderr(&mut self, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        // Exact native stdin progress messages carry no failure or private data.
        // Keep their count without making every noninteractive Codex run unknown.
        if matches!(
            text,
            "Reading prompt from stdin..." | "Reading additional input from stdin..."
        ) {
            self.stderr_informational_lines += 1;
            return;
        }
        let lower = text.to_ascii_lowercase();
        let category = if [
            "permission denied",
            "permission_denied",
            "tool denied",
            "tool execution denied",
            "not authorized",
            "access denied",
        ]
        .iter()
        .any(|p| lower.contains(p))
        {
            Some("permission denial")
        } else if [
            "resource_exhausted",
            "quota exhausted",
            "quota exceeded",
            "quota reached",
            "rate limit exceeded",
        ]
        .iter()
        .any(|p| lower.contains(p))
        {
            Some("quota/rate limit failure")
        } else if [
            "authentication failed",
            "unauthenticated",
            "invalid api key",
            "invalid_api_key",
        ]
        .iter()
        .any(|p| lower.contains(p))
        {
            Some("authentication failure")
        } else {
            None
        };
        if let Some(category) = category {
            self.failed = true;
            if self.stderr_diagnostics.len() < 32 {
                self.stderr_diagnostics.push(category.into());
            }
        } else {
            self.stderr_unclassified_lines += 1;
        }
    }

    pub(crate) fn observe_value(&mut self, harness: &str, event: &Value) {
        self.model_evidence.observe(
            ["/model", "/model_name", "/part/model", "/message/model"]
                .into_iter()
                .filter_map(|pointer| event.pointer(pointer)),
        );
        self.usage.observe(event);
        self.trajectory.observe(harness, event);
        if harness == "claude-code" {
            self.cost.observe_claude_result(event)
        }
        self.observe_skill(harness, event);
        if self.model.is_none() {
            self.model = event
                .get("model")
                .or_else(|| event.get("model_name"))
                .or_else(|| event.pointer("/part/model"))
                .and_then(Value::as_str)
                .filter(|m| crate::safe_identity(m))
                .map(str::to_string);
        }
        let metadata = native_metadata(harness, event);
        let helper_event = metadata["type"] == "system" || metadata["type"] == "collab";
        if helper_event && self.native_event_count >= 256 {
            self.failed = true;
            self.native.incomplete();
            self.blockers
                .push("native helper evaluation limit exceeded".into());
        } else if bounded_native_metadata(&metadata) {
            self.native.observe(harness, &metadata);
        } else {
            self.failed = true;
            self.native.incomplete();
            self.blockers
                .push("native metadata evaluation bound exceeded".into());
        }
        if helper_event {
            self.native_event_count += 1;
        }
        let kind = event
            .get("type")
            .or_else(|| event.get("event"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let session = event
            .get("session_id")
            .or_else(|| event.get("thread_id"))
            .or_else(|| event.get("conversation_id"))
            // OpenCode spells it `sessionID`, on every event including its
            // error events, which is what makes its errors resumable at all.
            .or_else(|| event.get("sessionID"))
            .or_else(|| event.pointer("/step_update/conversation_id"))
            .and_then(Value::as_str);
        for pointer in [
            "/session_id",
            "/thread_id",
            "/conversation_id",
            "/sessionID",
            "/step_update/conversation_id",
        ] {
            if let Some(value) = event.pointer(pointer) {
                match value.as_str().filter(|s| valid_session(s)) {
                    Some(id) if session == Some(id) => (),
                    _ => {
                        self.failed = true;
                        self.blockers
                            .push("invalid or conflicting session identity".into());
                    }
                }
            }
        }
        if let Some(session) = session.filter(|s| valid_session(s)) {
            if let Some(previous) = &self.session {
                if previous != session {
                    self.failed = true;
                    self.blockers
                        .push("session identity changed within attempt".into());
                }
            } else {
                self.session = Some(session.into());
            }
        }
        if event
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|v| !v.is_empty())
            || event.get("error").is_some_and(|v| !v.is_null())
        {
            self.blockers.push("harness reported an error".into());
            self.failed = true;
        }
        if kind.contains("denied")
            || event
                .get("permission_denials")
                .and_then(Value::as_array)
                .is_some_and(|v| !v.is_empty())
        {
            self.failed = true;
            self.blockers
                .push("harness reported permission denials".into());
        }
        match (harness, kind) {
            ("codex", "thread.started") | ("claude-code", "system") | ("antigravity", "init") => (),

            (_, "turn.failed" | "error") => {
                self.failed = true;
                self.blockers.push("harness emitted an error".into());
            }

            ("claude-code" | "antigravity", "result") => {
                let result = event.get("result").filter(|value| value.is_object());
                let status = result
                    .and_then(|value| value.get("status"))
                    .or_else(|| event.get("status"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let subtype = result
                    .and_then(|value| value.get("subtype"))
                    .or_else(|| event.get("subtype"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let recognized_success = {
                    subtype == "success"
                        && event.get("is_error").and_then(Value::as_bool) == Some(false)
                        && event.get("result").and_then(Value::as_str).is_some()
                };
                let failed = !recognized_success
                    || event
                        .get("is_error")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    || matches!(
                        status.as_str(),
                        "error" | "failed" | "cancelled" | "timeout"
                    )
                    || subtype.starts_with("error")
                    || event.get("error").is_some_and(|v| !v.is_null());
                self.summary = event
                    .get("response")
                    .or_else(|| result.and_then(|value| value.get("response")))
                    .or_else(|| event.get("result"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .into();
                self.finish(failed);
            }

            // OpenCode's `run --format json` stream, observed on 1.18.30. Every
            // event is `{type, timestamp, sessionID, part}`; the work of a turn
            // is a sequence of steps, and only the reason on a step's finish
            // says whether the turn ended or another step follows.

            // OpenCode 2.0.32 also streams reasoning. It is nonterminal
            // metadata; never retain its text as an answer or native payload.
            (_, "tool_use") | ("antigravity", "tool_result") => (),

            (
                _,
                "assistant" | "user" | "step_update" | "turn.started" | "item.started"
                | "item.updated" | "stream_event",
            ) => (),
            _ => self.unknown_events += 1,
        }
    }
    fn finish(&mut self, failed: bool) {
        if self.terminal {
            self.failed = true;
            self.blockers.push("multiple terminal events".into());
        }
        self.terminal = true;
        self.failed |= failed;
    }
}
fn native_metadata(_harness: &str, event: &Value) -> Value {
    let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
    let subtype = event.get("subtype").and_then(Value::as_str).unwrap_or("");

    let mut out = json!({});
    let fields: &[&str] = match (kind, subtype) {
        ("system", "task_started") => &[
            "task_id",
            "task_type",
            "subagent_type",
            "spawn_depth",
            "is_backgrounded",
        ],
        ("system", "task_progress") => &["task_id"],
        ("system", "task_notification") => &["task_id", "status", "output_file"],
        ("result", _) => &[],
        _ => return out,
    };
    out["type"] = json!(kind);
    // Only the three known system subtypes are consumed; terminal subtypes
    // and arbitrary payload strings must not enter helper accounting.
    if kind == "system" {
        out["subtype"] = json!(subtype);
    }
    for field in fields {
        let value = event.get(field).filter(|v| match *field {
            "spawn_depth" => v.is_u64(),
            "is_backgrounded" => v.is_boolean(),
            _ => v.is_string(),
        });
        if let Some(value) = value {
            out[field] = value.clone();
        }
    }
    if matches!(
        (kind, subtype),
        ("system", "task_progress" | "task_notification")
    ) && let Some(tokens) = event.pointer("/usage/total_tokens").and_then(Value::as_u64)
    {
        out["usage"] = json!({"total_tokens":tokens});
    }
    if kind == "result"
        && let Some(stats) = event.get("subagent_stats")
    {
        let mut selected = json!({});
        for field in ["spawned", "completed", "max_depth"] {
            if let Some(value) = stats.get(field).and_then(Value::as_u64) {
                selected[field] = json!(value);
            }
        }
        for field in ["depth_limit", "concurrency_limit", "budget"] {
            if let Some(value) = stats
                .get("refused")
                .and_then(|v| v.get(field))
                .and_then(Value::as_u64)
            {
                if selected["refused"].is_null() {
                    selected["refused"] = json!({});
                }
                selected["refused"][field] = json!(value);
            }
        }
        if let Some(roles) = stats.get("by_type").and_then(Value::as_object) {
            selected["by_type"] = Value::Object(
                roles
                    .iter()
                    .filter(|(_, count)| count.is_u64())
                    .map(|(role, count)| (role.clone(), count.clone()))
                    .collect(),
            );
        }
        out["subagent_stats"] = selected;
    }
    out
}

fn bounded_native_metadata(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.len() <= 256
                && map
                    .iter()
                    .all(|(key, value)| key.len() <= 4096 && bounded_native_metadata(value))
        }
        Value::Array(items) => items.len() <= 256 && items.iter().all(bounded_native_metadata),
        Value::String(text) => text.len() <= 4096,
        // Native refusal accounting adds three provider-supplied counters.
        // Reject values outside the safe evaluation range before that parser.
        Value::Number(number) => number.as_u64().is_none_or(|n| n <= u64::MAX / 3),
        _ => true,
    }
}

fn valid_session(session: &str) -> bool {
    !session.trim().is_empty() && session.len() <= 4096 && !session.chars().any(char::is_control)
}
