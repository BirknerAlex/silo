//! `silo login`: password and OIDC device-code sign-in.
//!
//! The OIDC half runs the **device authorization grant** against the
//! identity provider directly, never through Silo. That matters for two
//! reasons: the server never sees the user's credentials, and the flow
//! works on a machine with no browser and no listening port (a CI runner,
//! an SSH session) — which a redirect-based flow cannot.
//!
//! The client learns the endpoints from the server's `GetAuthInfo` rather
//! than from local configuration, so an operator changing identity
//! providers doesn't require every user to edit a file.

use std::time::Duration;

use serde::Deserialize;
use silo_proto::v1::GetAuthInfoResponse;

/// Poll interval the spec tells us to use when the provider doesn't say.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Upper bound on the whole flow, in case a provider returns an
/// `expires_in` that never arrives or is absurdly long.
const MAX_WAIT: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// Runs the device flow to completion and returns the ID token.
pub async fn oidc_device_flow(info: &GetAuthInfoResponse) -> anyhow::Result<String> {
    if info.oidc_device_authorization_endpoint.is_empty() {
        anyhow::bail!(
            "this server's identity provider does not advertise a device authorization \
             endpoint, so `silo login` cannot use it. Ask an admin for an API token instead."
        );
    }

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let scopes = if info.oidc_scopes.is_empty() {
        "openid".to_string()
    } else {
        info.oidc_scopes.join(" ")
    };

    let authorization: DeviceAuthorization = http
        .post(&info.oidc_device_authorization_endpoint)
        .form(&[
            ("client_id", info.oidc_client_id.as_str()),
            ("scope", scopes.as_str()),
        ])
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("failed to start the device flow: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("the identity provider rejected the device request: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("the device authorization response was malformed: {e}"))?;

    println!();
    match &authorization.verification_uri_complete {
        // Providers that support it embed the code in the URL, which
        // removes the step users most often get wrong.
        Some(url) => println!("  Open this URL to sign in:\n    {url}"),
        None => println!(
            "  Open this URL to sign in:\n    {}\n\n  And enter the code:\n    {}",
            authorization.verification_uri, authorization.user_code
        ),
    }
    println!("\n  Waiting for you to finish signing in...");

    let mut interval = authorization
        .interval
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_POLL_INTERVAL);
    let deadline = std::time::Instant::now()
        + authorization
            .expires_in
            .map(Duration::from_secs)
            .unwrap_or(MAX_WAIT)
            .min(MAX_WAIT);

    loop {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("the sign-in code expired before it was used");
        }
        tokio::time::sleep(interval).await;

        let response: TokenResponse = http
            .post(&info.oidc_token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", authorization.device_code.as_str()),
                ("client_id", info.oidc_client_id.as_str()),
            ])
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("token request failed: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("token response was malformed: {e}"))?;

        match classify(&response) {
            PollOutcome::Pending => continue,
            PollOutcome::SlowDown => {
                // The provider is telling us we're polling too fast;
                // backing off is required, not optional.
                interval += Duration::from_secs(5);
            }
            PollOutcome::Done(id_token) => return Ok(id_token),
            PollOutcome::Failed(message) => anyhow::bail!("sign-in failed: {message}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PollOutcome {
    Pending,
    SlowDown,
    Done(String),
    Failed(String),
}

/// Interprets one device-token poll.
///
/// `authorization_pending` and `slow_down` are the two errors that mean
/// "keep going" rather than "give up"; treating them as failures is the
/// classic way to break this flow.
fn classify(response: &TokenResponse) -> PollOutcome {
    if let Some(error) = &response.error {
        return match error.as_str() {
            "authorization_pending" => PollOutcome::Pending,
            "slow_down" => PollOutcome::SlowDown,
            other => PollOutcome::Failed(
                response
                    .error_description
                    .clone()
                    .unwrap_or_else(|| other.to_string()),
            ),
        };
    }
    match &response.id_token {
        Some(token) => PollOutcome::Done(token.clone()),
        // A successful response with no `id_token` means `openid` wasn't
        // among the granted scopes — a configuration problem worth naming.
        None => PollOutcome::Failed(
            "the identity provider returned no id_token; is the `openid` scope configured?"
                .to_string(),
        ),
    }
}

/// Reads a password without echoing it. Falls back to stdin when the
/// process has no TTY, so `echo hunter2 | silo login` works in scripts.
pub fn prompt_password(prompt: &str) -> anyhow::Result<String> {
    if atty_stdin() {
        return Ok(rpassword::prompt_password(prompt)?);
    }
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

pub fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
    Ok(line.trim().to_string())
}

fn atty_stdin() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}

/// True when there is a person on the other end who could answer a
/// prompt. Both halves matter: a CI runner has neither, and a process with
/// piped stdin but a terminal stdout would still have nowhere to read an
/// answer from.
pub fn is_interactive() -> bool {
    atty_stdin() && std::io::IsTerminal::is_terminal(&std::io::stdout())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(error: Option<&str>, id_token: Option<&str>) -> TokenResponse {
        TokenResponse {
            id_token: id_token.map(String::from),
            error: error.map(String::from),
            error_description: None,
        }
    }

    #[test]
    fn pending_and_slow_down_mean_keep_polling() {
        assert_eq!(
            classify(&response(Some("authorization_pending"), None)),
            PollOutcome::Pending
        );
        assert_eq!(
            classify(&response(Some("slow_down"), None)),
            PollOutcome::SlowDown
        );
    }

    #[test]
    fn an_id_token_completes_the_flow() {
        assert_eq!(
            classify(&response(None, Some("jwt-here"))),
            PollOutcome::Done("jwt-here".into())
        );
    }

    #[test]
    fn terminal_errors_stop_the_flow() {
        assert!(matches!(
            classify(&response(Some("access_denied"), None)),
            PollOutcome::Failed(_)
        ));
        assert!(matches!(
            classify(&response(Some("expired_token"), None)),
            PollOutcome::Failed(_)
        ));
    }

    #[test]
    fn error_descriptions_are_preferred_over_error_codes() {
        let response = TokenResponse {
            id_token: None,
            error: Some("invalid_client".into()),
            error_description: Some("client is not enabled for device flow".into()),
        };
        assert_eq!(
            classify(&response),
            PollOutcome::Failed("client is not enabled for device flow".into())
        );
    }

    #[test]
    fn a_success_without_an_id_token_names_the_likely_cause() {
        let PollOutcome::Failed(message) = classify(&response(None, None)) else {
            panic!("expected a failure");
        };
        assert!(message.contains("openid"), "got: {message}");
    }

    #[test]
    fn device_authorization_responses_tolerate_missing_optional_fields() {
        let parsed: DeviceAuthorization = serde_json::from_str(
            r#"{"device_code":"d","user_code":"WXYZ","verification_uri":"https://id/device"}"#,
        )
        .unwrap();
        assert_eq!(parsed.user_code, "WXYZ");
        assert!(parsed.interval.is_none());
        assert!(parsed.verification_uri_complete.is_none());
    }
}
