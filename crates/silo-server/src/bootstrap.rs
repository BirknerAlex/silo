//! First-run bootstrap.
//!
//! A registry with no credentials is unusable, and a registry whose
//! credential is baked into a config file is one that everybody ships to
//! production unchanged. So the first startup against an empty database
//! mints an admin token and an admin user, prints them to stdout exactly
//! once, and never does so again — the secrets are only ever stored
//! hashed.
//!
//! The output goes to stdout rather than the tracing log on purpose: it's
//! a one-time operator handoff, not a diagnostic, and it must survive
//! `RUST_LOG` being set to something quiet.

use silo_db::audit::{self, Actor, AuditEntry};
use silo_db::tokens::{NewToken, Permission, Scope, TokenKind};
use silo_db::Db;

use silo_core::config::AuthConfig;

/// What bootstrap did, so the caller can log a summary and tests can
/// assert on it without scraping stdout.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BootstrapResult {
    pub token_created: bool,
    pub user_created: bool,
}

/// Creates the initial admin credentials if the database has none.
///
/// Both halves are independent: a deployment that already has an admin
/// token but lost its user (or vice versa) gets only the missing half
/// back, rather than an all-or-nothing retry.
pub async fn run(db: &Db, cfg: &AuthConfig) -> anyhow::Result<BootstrapResult> {
    let mut result = BootstrapResult::default();
    if !cfg.bootstrap {
        return Ok(result);
    }

    if !db.has_any_api_token().await? {
        let issued = db
            .create_token(
                NewToken {
                    name: cfg.bootstrap_token_name.clone(),
                    permission: Permission::Admin,
                    kind: TokenKind::Api,
                    scope: Scope::All,
                    user_id: None,
                    created_by: None,
                    expires_at: None,
                },
                cfg.token_pepper.as_deref(),
            )
            .await?;
        result.token_created = true;

        println!("{}", banner("SILO BOOTSTRAP TOKEN"));
        println!("  A bootstrap admin token has been created because this database had none.");
        println!("  It is stored only as a salted hash — this is the one time it is printed.");
        println!();
        println!("    name:  {}", issued.token.name);
        println!("    scope: all repos, admin permission, never expires");
        println!("    token: {}", issued.secret);
        println!();
        println!("  Save it, then create narrower tokens with:");
        println!("    silo token create --name ci --permission write --repo myrepo");
        println!("  and revoke this one with:");
        println!("    silo token revoke --name {}", issued.token.name);
        println!("{}", "=".repeat(72));

        db.record_audit(
            AuditEntry::new(audit::action::SERVER_BOOTSTRAP, &Actor::system())
                .target(&issued.token.name)
                .detail(serde_json::json!({ "kind": "token" })),
        )
        .await;
    }

    if !db.has_any_user().await? {
        let password = generate_password();
        let user = db
            .create_user(&cfg.bootstrap_username, Some(&password), true)
            .await?;
        result.user_created = true;

        println!("{}", banner("SILO BOOTSTRAP USER"));
        println!("  An admin user has been created so `silo login` works out of the box.");
        println!("  The password is stored only as an argon2id hash.");
        println!();
        println!("    username: {}", user.username);
        println!("    password: {password}");
        println!();
        println!("  Change it with:");
        println!("    silo user set-password --username {}", user.username);
        println!("{}", "=".repeat(72));

        db.record_audit(
            AuditEntry::new(audit::action::SERVER_BOOTSTRAP, &Actor::system())
                .target(&user.username)
                .detail(serde_json::json!({ "kind": "user" })),
        )
        .await;
    }

    Ok(result)
}

fn banner(title: &str) -> String {
    format!("\n{}\n  {title}\n{}", "=".repeat(72), "-".repeat(72))
}

/// A 24-character password from a CSPRNG. The alphabet omits characters
/// that are easy to confuse when transcribed from a terminal (`0`/`O`,
/// `1`/`l`/`I`), because this password's whole job is to be read off a
/// screen once and typed somewhere else.
fn generate_password() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passwords_are_long_and_unambiguous() {
        let password = generate_password();
        assert_eq!(password.len(), 24);
        for c in password.chars() {
            assert!(c.is_ascii_alphanumeric(), "unexpected character {c:?}");
            assert!(
                !matches!(c, '0' | 'O' | '1' | 'l' | 'I'),
                "{c:?} is easy to misread when transcribed"
            );
        }
    }

    #[test]
    fn generated_passwords_differ_between_calls() {
        let a = generate_password();
        let b = generate_password();
        assert_ne!(a, b);
    }

    #[test]
    fn banner_is_visually_delimited() {
        let banner = banner("TEST");
        assert!(banner.contains("TEST"));
        assert!(banner.contains(&"=".repeat(72)));
    }

    #[test]
    fn result_defaults_to_having_done_nothing() {
        assert_eq!(
            BootstrapResult::default(),
            BootstrapResult {
                token_created: false,
                user_created: false
            }
        );
    }
}
