use ahu_harness_native::call;
use serde_json::{Value, json};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::{fs, path::PathBuf};

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    exe: PathBuf,
}
impl Fixture {
    fn new(body: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let home = root.join("home");
        fs::create_dir(&home).unwrap();
        let exe = root.join("native");
        fs::write(&exe, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _tmp: tmp,
            root,
            home,
            exe,
        }
    }
    fn probe(&self) -> Value {
        json!({"project":self.root,"home":self.home,"native_executable":self.exe,"environment":{}})
    }
    fn setup(&self) -> Value {
        json!({"project":self.root,"home":self.home,"ahu_executable":self.exe,"skills":[]})
    }
}

#[test]
fn setup_proposes_all_provider_formats_and_never_writes() {
    let f = Fixture::new("exit 99");
    for h in ["claude-code"] {
        let mut p = f.setup();
        p["skills"] = json!([{"name":"test-skill","text":"# synthetic\n"}]);
        let result = call(h, "setup", &p).unwrap();
        let changes = result["changes"].as_array().unwrap();
        assert!(changes.len() >= 2);
        for change in changes {
            assert!(change["expected_before_sha256"].is_null());
            assert!(!PathBuf::from(change["path"].as_str().unwrap()).exists());
        }
        let text = changes[0]["text"].as_str().unwrap();
        if h == "codex" {
            let v: toml::Value = toml::from_str(text).unwrap();
            assert_eq!(
                v["mcp_servers"]["ahu"]["tools"]["ahu_agents_list"]["approval_mode"].as_str(),
                Some("approve")
            );
        } else {
            let v: Value = serde_json::from_str(text).unwrap();
            let key = if h == "opencode" { "mcp" } else { "mcpServers" };
            assert!(v[key]["ahu"].is_object());
            if h == "kiro" {
                assert_eq!(v[key]["ahu"]["env"]["AHU_TASK_ID"], "${AHU_TASK_ID}");
            }
        }
    }
}

#[test]
fn auth_returns_stable_fingerprint_without_identity_or_raw_output() {
    use sha2::{Digest, Sha256};
    let f = Fixture::new(
        "printf '{\"loggedIn\":true,\"email\":\"fixture@example.invalid\",\"orgId\":\"synthetic-org\",\"authMethod\":\"oauth\",\"apiProvider\":\"anthropic\",\"token\":\"private-sentinel\"}'",
    );
    let result = call("claude-code", "auth", &f.probe()).unwrap();
    let identity = json!({"harness":"claude-code","identity_kind":"oauth/anthropic","principal":"fixture@example.invalid","organization":"synthetic-org","workspace":null});
    let expected = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&identity).unwrap())
    );
    assert_eq!(result["fingerprint"], expected);
    assert!(!result.to_string().contains("fixture@"));
    assert!(!result.to_string().contains("private-sentinel"));
    {
        let h = "claude-code";
        assert_eq!(
            call(h, "budget", &f.probe()).unwrap()["status"],
            "unsupported"
        );
    }
}

#[test]
fn inventory_and_import_are_passive_and_reject_path_escape() {
    let f = Fixture::new("touch activated");
    let source = f.root.join("agent.md");
    fs::write(
        &source,
        "---\nmodel: exact-model\nhooks:\n  start: do-not-run\n---\nRead only.\n",
    )
    .unwrap();
    let p =
        json!({"project":f.root,"home":f.home,"import":{"path":source,"format":"claude-agent"}});
    let result = call("claude-code", "native_sources", &p).unwrap();
    assert_eq!(result["imported"]["instructions"], "Read only.\n");
    assert_eq!(result["imported"]["settings_applied"], false);
    assert!(!f.root.join("activated").exists());
    let mut p = p;
    p["import"]["path"] = json!(f.root.join("../outside"));
    assert!(call("claude-code", "native_sources", &p).is_err());
}

#[test]
fn masked_native_overrides_never_probe_the_default_account() {
    let f = Fixture::new("touch should-not-run; exit 99");
    for (harness, variable) in [
        ("codex", "CODEX_HOME"),
        ("claude-code", "ANTHROPIC_API_KEY"),
        ("opencode", "OLLAMA_HOST"),
        ("kiro", "KIRO_HOME"),
        ("antigravity", "GEMINI_API_KEY"),
    ] {
        let mut p = f.probe();
        p["environment_names"] = json!([variable]);
        assert!(call(harness, "auth", &p).is_err());
        assert!(call(harness, "budget", &p).is_err());
    }
    assert!(!f.root.join("should-not-run").exists());
}

#[test]
fn native_hook_view_redacts_commands_and_reports_unknown_scope() {
    let f = Fixture::new("exit 99");
    fs::create_dir(f.root.join(".claude")).unwrap();
    fs::write(f.root.join(".claude/settings.json"), r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"tool private-sentinel"}]}]},"permissions":{"defaultMode":"bypassPermissions"}}"#).unwrap();
    let mut p =
        json!({"project":f.root,"home":f.home,"settings":{"view":"hooks","environment_names":[]}});
    let v = call("claude-code", "native_sources", &p).unwrap();
    assert_eq!(v["hooks"].as_array().unwrap().len(), 1);
    assert!(!v.to_string().contains("private-sentinel"));
    assert_eq!(v["settings"][0]["approvals_widened"], true);
    p["settings"]["environment_names"] = json!(["CLAUDE_CONFIG_DIR"]);
    let v = call("claude-code", "native_sources", &p).unwrap();
    assert_eq!(v["unscanned_harness"], "claude-code");
    assert!(!v["unreadable"].as_array().unwrap().is_empty());
}

#[test]
fn hook_discovery_refuses_symlinked_native_configuration() {
    let f = Fixture::new("exit 99");
    let outside = f.root.join("outside-config");
    fs::create_dir(&outside).unwrap();
    fs::write(
        outside.join("settings.json"),
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"private-sentinel"}]}]}}"#,
    )
    .unwrap();
    symlink(&outside, f.root.join(".claude")).unwrap();
    let p =
        json!({"project":f.root,"home":f.home,"settings":{"view":"hooks","environment_names":[]}});
    let result = call("claude-code", "native_sources", &p).unwrap();
    assert!(result["hooks"].as_array().unwrap().is_empty());
    assert!(!result["unreadable"].as_array().unwrap().is_empty());
    assert!(!result.to_string().contains("private-sentinel"));
}
