use crate::util::{Error, Result, digest_bytes};
use serde_json::{Value, json};
use std::path::Path;
pub struct Identity {
    pub harness: String,
    pub identity_kind: String,
    pub principal: String,
    pub organization: Option<String>,
    pub workspace: Option<String>,
}

impl Identity {
    fn fingerprint(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&json!({
            "harness": self.harness,
            "identity_kind": self.identity_kind,
            "principal": self.principal,
            "organization": self.organization,
            "workspace": self.workspace,
        }))?;
        Ok(digest_bytes(&bytes))
    }
}

fn probe_claude(
    executable: &Path,
    cwd: &Path,
    home: &Path,
    environment: &crate::Environment,
) -> Result<Identity> {
    let output = crate::process::run(
        executable,
        &["auth", "status", "--json"],
        cwd,
        home,
        environment,
        std::time::Duration::from_secs(8),
    )?;
    let value: Value = serde_json::from_slice(&output)
        .map_err(|_| Error::new("Claude auth status returned invalid JSON"))?;
    if value.get("loggedIn").and_then(Value::as_bool) != Some(true) {
        return Err(Error::diagnosed(crate::Diagnostic::NotSignedIn));
    }
    let principal = value
        .get("email")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::new("Claude auth status does not expose a verifiable account identity")
        })?;
    let org = value
        .get("orgId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let auth_method = value
        .get("authMethod")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Ok(Identity {
        harness: "claude-code".into(),
        identity_kind: format!(
            "{auth_method}/{}",
            value
                .get("apiProvider")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ),
        principal: principal.into(),
        organization: org.map(str::to_owned),
        workspace: None,
    })
}

// Open agy in the checkout interactively and review its prompt; ahu never
// approves native folder trust automatically.

pub(crate) fn call(
    harness: &str,
    p: &crate::ProbeParams,
    budget: bool,
    _model: Option<&str>,
    _ollama_host: Option<&str>,
    requested_identity: Option<&str>,
) -> Result<Value> {
    if requested_identity
        .is_some_and(|id| id != harness && !(harness == "opencode" && id == "ollama"))
    {
        return Err(Error::invalid());
    }
    if budget {
        {
            return Ok(json!({"status":"unsupported","windows":[],"signal_type":"unknown"}));
        }
    }

    let identity = match harness {
        "claude-code" => probe_claude(&p.native_executable, &p.project, &p.home, &p.environment)?,

        _ => return Err(Error::invalid()),
    };
    Ok(
        json!({"status":"available","binding_harness":identity.harness,"fingerprint":identity.fingerprint()?,"effective_provider_address_verified":harness!="opencode","identity_kind":identity.identity_kind}),
    )
}
