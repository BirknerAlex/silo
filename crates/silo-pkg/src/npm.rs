//! npm: tarball parsing, registry layout, and packument generation.
//!
//! An npm package is a gzipped tar with everything under a single top
//! level directory (`package/` by convention, but npm itself only assumes
//! *some* single prefix), and `package.json` at its root. The registry
//! "index" for a package is its packument: one JSON document listing every
//! published version plus `dist-tags`. Like apk — and unlike rpm — that's
//! a pure function of stored metadata, so republishing never reads
//! tarballs back out of object storage.
//!
//! `dist.tarball` has to be an absolute URL, but the right absolute URL
//! depends on how the server is reached (direct, behind a proxy, under a
//! different hostname per environment). Rather than baking a guess into
//! stored bytes, the packument is stored with [`BASE_URL_PLACEHOLDER`] and
//! the HTTP layer substitutes the real base at serve time.

use std::io::Read;
use std::pin::Pin;

use base64::Engine;
use serde_json::{json, Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha512};

use crate::{Format, IndexContext, IndexObject, PackageFormat, ParseError, ParsedPackage};

pub struct NpmFormat;

/// Stand-in for the server's public base URL inside stored packuments.
/// Substituted per-request so one stored document serves every hostname
/// the registry is reachable under.
pub const BASE_URL_PLACEHOLDER: &str = "__SILO_BASE_URL__";

/// Name of the packument object within a package's index prefix.
pub const PACKUMENT_OBJECT: &str = "packument.json";

impl Format for NpmFormat {
    fn format(&self) -> PackageFormat {
        PackageFormat::Npm
    }

    fn parse(&self, bytes: &[u8]) -> Result<ParsedPackage, ParseError> {
        let manifest = read_package_json(bytes)?;

        let name = manifest
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| ParseError::invalid("package.json is missing `name`"))?
            .to_string();
        let version = manifest
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| ParseError::invalid("package.json is missing `version`"))?
            .to_string();
        validate_name(&name)?;
        if semver::Version::parse(&version).is_err() {
            return Err(ParseError::invalid(format!(
                "`{version}` is not a valid semver version"
            )));
        }

        let filename = tarball_filename(&name, &version);

        // npm clients verify `integrity` (sha512) and legacy clients
        // verify `shasum` (sha1), so both are computed once at publish
        // time and stored rather than recomputed per packument render.
        let shasum = hex::encode(<Sha1 as sha1::Digest>::digest(bytes));
        let integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
        );

        let mut manifest = manifest;
        manifest.insert(
            "dist".to_string(),
            json!({
                "shasum": shasum,
                "integrity": integrity,
                "tarball": Value::Null, // filled in by `packument_entry`
            }),
        );

        Ok(ParsedPackage {
            format: PackageFormat::Npm,
            name,
            epoch: 0,
            version,
            release: String::new(),
            // npm packages are platform-independent as far as the registry
            // is concerned; per-platform binaries ship as separate packages.
            arch: "any".to_string(),
            filename,
            metadata: Value::Object(manifest),
            payload: bytes.to_vec(),
        })
    }

    fn storage_key(&self, repo: &str, channel: &str, pkg: &ParsedPackage) -> String {
        format!(
            "{}/-/{}",
            package_prefix(repo, channel, &pkg.name),
            pkg.filename
        )
    }

    /// One packument per package name, so publishes of unrelated packages
    /// never contend on the same index lock.
    fn index_group(&self, pkg: &ParsedPackage) -> String {
        pkg.name.clone()
    }

    fn index_prefix(&self, repo: &str, channel: &str, group: &str) -> String {
        package_prefix(repo, channel, group)
    }

    fn build_index<'a>(
        &'a self,
        ctx: &'a IndexContext<'a>,
    ) -> Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<IndexObject>>> + Send + 'a>>
    {
        Box::pin(async move {
            let packument = render_packument(ctx.repo, ctx.channel, ctx.group, ctx.records);
            let mut bytes = serde_json::to_vec(&packument)?;
            if let Some(base) = ctx.public_base_url {
                bytes = substitute_base_url(&bytes, base);
            }
            Ok(vec![IndexObject {
                name: PACKUMENT_OBJECT.to_string(),
                bytes,
                content_type: "application/json",
            }])
        })
    }
}

pub fn npm_prefix(repo: &str, channel: &str) -> String {
    format!("{repo}/{channel}/npm")
}

pub fn package_prefix(repo: &str, channel: &str, name: &str) -> String {
    format!("{}/{name}", npm_prefix(repo, channel))
}

/// npm's tarball naming drops the scope: `@acme/widget` at 1.0.0 ships as
/// `widget-1.0.0.tgz`.
pub fn tarball_filename(name: &str, version: &str) -> String {
    let unscoped = name.rsplit('/').next().unwrap_or(name);
    format!("{unscoped}-{version}.tgz")
}

/// Replaces [`BASE_URL_PLACEHOLDER`] in a stored packument with the base
/// URL this request arrived on. Trailing slashes are trimmed so the result
/// never contains `//`.
pub fn substitute_base_url(bytes: &[u8], base_url: &str) -> Vec<u8> {
    let base = base_url.trim_end_matches('/');
    let text = String::from_utf8_lossy(bytes);
    text.replace(BASE_URL_PLACEHOLDER, base).into_bytes()
}

/// Builds the full packument document for one package name.
pub fn render_packument(
    repo: &str,
    channel: &str,
    name: &str,
    records: &[crate::PackageRecord],
) -> Value {
    let mut versions = Map::new();
    let mut time = Map::new();

    for record in records {
        versions.insert(
            record.version.clone(),
            packument_entry(repo, channel, record),
        );
        time.insert(
            record.version.clone(),
            Value::String(format_rfc3339(record.published_at)),
        );
    }

    let mut dist_tags = Map::new();
    if let Some(latest) = latest_version(records) {
        dist_tags.insert("latest".to_string(), Value::String(latest));
    }

    json!({
        "_id": name,
        "name": name,
        "dist-tags": Value::Object(dist_tags),
        "versions": Value::Object(versions),
        "time": Value::Object(time),
    })
}

/// One `versions[x.y.z]` entry: the published `package.json` with `dist`
/// rewritten to point at this registry.
fn packument_entry(repo: &str, channel: &str, record: &crate::PackageRecord) -> Value {
    let mut entry = match record.metadata.clone() {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    entry.insert("name".to_string(), Value::String(record.name.clone()));
    entry.insert("version".to_string(), Value::String(record.version.clone()));

    let mut dist = match entry.get("dist").cloned() {
        Some(Value::Object(map)) => map,
        _ => Map::new(),
    };
    dist.insert(
        "tarball".to_string(),
        Value::String(format!(
            "{BASE_URL_PLACEHOLDER}/{}/-/{}",
            package_prefix(repo, channel, &record.name),
            record.filename
        )),
    );
    if !dist.contains_key("shasum") {
        dist.insert("shasum".to_string(), Value::String(record.sha256.clone()));
    }
    dist.insert(
        "fileCount".to_string(),
        Value::Number(serde_json::Number::from(1u64)),
    );
    dist.insert(
        "unpackedSize".to_string(),
        Value::Number(serde_json::Number::from(record.size_bytes.max(0) as u64)),
    );
    entry.insert("dist".to_string(), Value::Object(dist));
    entry.insert(
        "_id".to_string(),
        Value::String(format!("{}@{}", record.name, record.version)),
    );
    Value::Object(entry)
}

/// Highest stable semver, falling back to the highest prerelease when a
/// package has only ever published prereleases. Anything unparseable is
/// ignored — `parse` rejects those at publish time, so they can only come
/// from rows written by an older schema.
fn latest_version(records: &[crate::PackageRecord]) -> Option<String> {
    let parsed: Vec<semver::Version> = records
        .iter()
        .filter_map(|r| semver::Version::parse(&r.version).ok())
        .collect();
    parsed
        .iter()
        .filter(|v| v.pre.is_empty())
        .max()
        .or_else(|| parsed.iter().max())
        .map(|v| v.to_string())
}

/// Minimal RFC 3339 formatter for packument `time` entries. Pulling in a
/// date-time crate for one output format isn't worth it, and npm only ever
/// reads these back as opaque display strings.
fn format_rfc3339(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let secs_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days`, shifted to a March-based year so
/// leap days land at the end of the cycle.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// npm's own name rules, minus the deprecated-but-legal historical names:
/// lowercase, URL-safe, optionally scoped, at most 214 characters.
fn validate_name(name: &str) -> Result<(), ParseError> {
    if name.is_empty() || name.len() > 214 {
        return Err(ParseError::invalid(
            "npm package name length is out of range",
        ));
    }
    if name != name.to_ascii_lowercase() {
        return Err(ParseError::invalid("npm package names must be lowercase"));
    }
    let body = match name.strip_prefix('@') {
        Some(scoped) => {
            let (scope, rest) = scoped.split_once('/').ok_or_else(|| {
                ParseError::invalid("scoped npm names must be of the form @scope/name")
            })?;
            if scope.is_empty() || rest.is_empty() {
                return Err(ParseError::invalid("scoped npm names must be @scope/name"));
            }
            if !scope.chars().all(is_name_char) {
                return Err(ParseError::invalid("invalid character in npm scope"));
            }
            rest
        }
        None => name,
    };
    if body.starts_with('.') || body.starts_with('_') || !body.chars().all(is_name_char) {
        return Err(ParseError::invalid(format!(
            "`{name}` is not a valid npm package name"
        )));
    }
    Ok(())
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | '~')
}

/// Finds `<prefix>/package.json` in the tarball. npm always writes a
/// single top-level directory but doesn't guarantee it's named `package`
/// (`npm pack` of a scoped package historically differed), so the prefix
/// is taken from the entry itself rather than assumed.
fn read_package_json(bytes: &[u8]) -> Result<Map<String, Value>, ParseError> {
    let mut inflated = Vec::new();
    flate2::bufread::MultiGzDecoder::new(bytes)
        .read_to_end(&mut inflated)
        .map_err(|e| ParseError::invalid(format!("not a gzipped tarball: {e}")))?;

    let mut archive = tar::Archive::new(inflated.as_slice());
    for entry in archive
        .entries()
        .map_err(|e| ParseError::invalid(format!("corrupt tarball: {e}")))?
    {
        let mut entry = entry.map_err(|e| ParseError::invalid(format!("corrupt tarball: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| ParseError::invalid(format!("bad tar path: {e}")))?
            .to_string_lossy()
            .into_owned();
        let components: Vec<&str> = path.trim_start_matches("./").split('/').collect();
        if components.len() == 2 && components[1] == "package.json" {
            let mut text = String::new();
            entry
                .read_to_string(&mut text)
                .map_err(|e| ParseError::invalid(format!("unreadable package.json: {e}")))?;
            return match serde_json::from_str(&text) {
                Ok(Value::Object(map)) => Ok(map),
                Ok(_) => Err(ParseError::invalid("package.json is not a JSON object")),
                Err(e) => Err(ParseError::invalid(format!("invalid package.json: {e}"))),
            };
        }
    }
    Err(ParseError::invalid(
        "tarball contains no <prefix>/package.json",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_test_npm;
    use crate::PackageRecord;

    fn record(name: &str, version: &str) -> PackageRecord {
        PackageRecord {
            format: PackageFormat::Npm,
            name: name.into(),
            epoch: 0,
            version: version.into(),
            release: String::new(),
            arch: "any".into(),
            filename: tarball_filename(name, version),
            storage_key: "irrelevant".into(),
            size_bytes: 42,
            sha256: "abc".into(),
            metadata: json!({
                "name": name,
                "version": version,
                "description": "a test package",
                "dist": { "shasum": "abc", "integrity": "sha512-xyz" },
            }),
            published_at: 1_700_000_000,
        }
    }

    #[test]
    fn parses_a_generated_tarball() {
        let bytes = build_test_npm("widget", "1.2.3");
        let parsed = NpmFormat.parse(&bytes).expect("parse npm tarball");
        assert_eq!(parsed.name, "widget");
        assert_eq!(parsed.version, "1.2.3");
        assert_eq!(parsed.filename, "widget-1.2.3.tgz");
        assert_eq!(parsed.arch, "any");
        let dist = &parsed.metadata["dist"];
        assert!(dist["integrity"].as_str().unwrap().starts_with("sha512-"));
        assert_eq!(dist["shasum"].as_str().unwrap().len(), 40);
    }

    #[test]
    fn scoped_packages_keep_the_scope_in_the_path_but_not_the_filename() {
        let bytes = build_test_npm("@acme/widget", "1.0.0");
        let parsed = NpmFormat.parse(&bytes).unwrap();
        assert_eq!(parsed.name, "@acme/widget");
        assert_eq!(parsed.filename, "widget-1.0.0.tgz");
        assert_eq!(
            NpmFormat.storage_key("r", "c", &parsed),
            "r/c/npm/@acme/widget/-/widget-1.0.0.tgz"
        );
        assert_eq!(NpmFormat.index_group(&parsed), "@acme/widget");
    }

    #[test]
    fn rejects_a_tarball_without_package_json() {
        let bytes = super::super::apk::gzip(
            super::super::apk::tar_bytes(&[("package/README", b"hi".as_slice())]).unwrap(),
        )
        .unwrap();
        assert!(NpmFormat.parse(&bytes).is_err());
    }

    #[test]
    fn rejects_non_semver_versions() {
        let bytes = build_test_npm("widget", "not-a-version");
        assert!(NpmFormat.parse(&bytes).is_err());
    }

    #[test]
    fn rejects_uppercase_and_malformed_names() {
        assert!(validate_name("Widget").is_err());
        assert!(validate_name("@scope").is_err());
        assert!(validate_name("_leading-underscore").is_err());
        assert!(validate_name("has space").is_err());
        assert!(validate_name("@acme/widget").is_ok());
        assert!(validate_name("widget.js").is_ok());
    }

    #[test]
    fn packument_lists_versions_and_picks_latest_stable() {
        let records = [
            record("widget", "1.0.0"),
            record("widget", "2.0.0"),
            record("widget", "3.0.0-beta.1"),
        ];
        let doc = render_packument("r", "c", "widget", &records);
        assert_eq!(doc["dist-tags"]["latest"], "2.0.0");
        assert_eq!(doc["versions"].as_object().unwrap().len(), 3);
        assert_eq!(doc["versions"]["1.0.0"]["_id"], "widget@1.0.0");
    }

    #[test]
    fn packument_falls_back_to_a_prerelease_when_nothing_stable_exists() {
        let records = [record("widget", "1.0.0-rc.1")];
        let doc = render_packument("r", "c", "widget", &records);
        assert_eq!(doc["dist-tags"]["latest"], "1.0.0-rc.1");
    }

    #[test]
    fn packument_has_no_latest_tag_when_empty() {
        let doc = render_packument("r", "c", "widget", &[]);
        assert!(doc["dist-tags"].as_object().unwrap().is_empty());
    }

    #[test]
    fn tarball_urls_are_placeholders_until_a_base_url_is_known() {
        let records = [record("widget", "1.0.0")];
        let doc = render_packument("r", "c", "widget", &records);
        let url = doc["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert_eq!(url, "__SILO_BASE_URL__/r/c/npm/widget/-/widget-1.0.0.tgz");

        let substituted = substitute_base_url(
            serde_json::to_string(&doc).unwrap().as_bytes(),
            "https://silo.example.com/",
        );
        let doc: Value = serde_json::from_slice(&substituted).unwrap();
        assert_eq!(
            doc["versions"]["1.0.0"]["dist"]["tarball"],
            "https://silo.example.com/r/c/npm/widget/-/widget-1.0.0.tgz"
        );
    }

    #[test]
    fn formats_unix_seconds_as_rfc3339() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20.000Z");
    }

    #[tokio::test]
    async fn build_index_emits_one_packument_object() {
        let records = [record("widget", "1.0.0")];
        let ctx = IndexContext {
            repo: "r",
            channel: "c",
            group: "widget",
            records: &records,
            public_base_url: Some("https://silo.example.com"),
            signer: None,
        };
        let objects = NpmFormat.build_index(&ctx).await.unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].name, PACKUMENT_OBJECT);
        let doc: Value = serde_json::from_slice(&objects[0].bytes).unwrap();
        assert_eq!(
            doc["versions"]["1.0.0"]["dist"]["tarball"],
            "https://silo.example.com/r/c/npm/widget/-/widget-1.0.0.tgz"
        );
    }
}
