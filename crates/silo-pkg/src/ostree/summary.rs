//! The files that turn a pile of objects into a remote clients can use:
//! `summary`, its signature, the per-commit signature file, and `config`.
//!
//! `summary` is the one mutable file in an OSTree repository. It lists
//! every ref with its commit's checksum and size, so a client learns what
//! is available — and which commit each ref points at — with one request.
//! It is a pure function of the refs, which is what lets silo regenerate
//! it from database rows.
//!
//! ```text
//! summary     (a(s(taya{sv})) a{sv})
//!               refs           repository metadata
//! ```
//!
//! Each ref carries its commit size and checksum plus a metadata
//! dictionary holding the commit timestamp. Flatpak adds `xa.cache` to the
//! repository metadata — each ref's installed size, download size and
//! `metadata` keyfile — so listing apps doesn't mean fetching every
//! commit.
//!
//! Byte order is not uniform, and the layout below is what a real
//! `ostree`/`flatpak` repository contains rather than what the formats'
//! documentation implies:
//!
//! - a ref's commit size is native (little-endian) — it is a plain
//!   field of the summary, not a stored-on-disk value;
//! - commit timestamps, `ostree.summary.last-modified` and the sizes in
//!   `xa.cache` are big-endian;
//! - `xa.cache` is a variant inside the variant that holds it, which
//!   Flatpak's own reader asserts on.

use super::gvariant::{Ty, Value};
use super::object::Checksum;

/// One ref's entry in the summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryRef {
    pub name: String,
    pub commit: Checksum,
    /// Size in bytes of the commit object.
    pub commit_size: u64,
    /// Commit timestamp, seconds since the epoch.
    pub timestamp: u64,
    pub installed_size: u64,
    pub download_size: u64,
    /// The app's `metadata` keyfile, or empty.
    pub metadata: String,
}

/// Renders `summary`. Refs are sorted by name, which clients rely on when
/// they search it.
pub fn render_summary(refs: &[SummaryRef], last_modified: u64) -> Vec<u8> {
    let mut sorted: Vec<&SummaryRef> = refs.iter().collect();
    sorted.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));

    let ref_entries: Vec<Value> = sorted
        .iter()
        .map(|r| {
            Value::Tuple(vec![
                Value::str(&r.name),
                Value::Tuple(vec![
                    Value::U64(r.commit_size),
                    Value::Bytes(r.commit.0.to_vec()),
                    Value::dict(vec![Value::entry(
                        "ostree.commit.timestamp",
                        Value::U64(r.timestamp.swap_bytes()),
                    )]),
                ]),
            ])
        })
        .collect();

    let cache_entries: Vec<Value> = sorted
        .iter()
        .map(|r| {
            Value::Tuple(vec![
                Value::str(&r.name),
                Value::Tuple(vec![
                    Value::U64(r.installed_size.swap_bytes()),
                    Value::U64(r.download_size.swap_bytes()),
                    Value::str(&r.metadata),
                ]),
            ])
        })
        .collect();

    let cache = Value::Array(Ty::parse("{s(tts)}").expect("static type"), cache_entries);
    let metadata = Value::dict(vec![
        Value::entry("ostree.summary.mode", Value::str("archive-z2")),
        Value::entry("ostree.summary.tombstone-commits", Value::Bool(false)),
        Value::entry(
            "ostree.summary.last-modified",
            Value::U64(last_modified.swap_bytes()),
        ),
        Value::entry("xa.cache-version", Value::U32(2)),
        // A variant within the variant `entry` already makes.
        Value::entry("xa.cache", Value::variant(cache)),
        Value::entry(
            "xa.sparse-cache",
            Value::Array(Ty::parse("{sa{sv}}").expect("static type"), vec![]),
        ),
    ]);

    Value::Tuple(vec![
        Value::Array(
            Ty::parse("(s(taya{sv}))").expect("static type"),
            ref_entries,
        ),
        metadata,
    ])
    .encode()
}

/// The `summary.sig` that carries detached OpenPGP signatures over
/// `summary`: an `a{sv}` with the signatures under `ostree.gpgsigs`.
pub fn render_signature_file(signatures: &[Vec<u8>]) -> Vec<u8> {
    gpg_sigs_dict(signatures).encode()
}

/// The `.commitmeta` object that carries signatures over a commit,
/// stored beside it.
pub fn render_commit_signatures(signatures: &[Vec<u8>]) -> Vec<u8> {
    gpg_sigs_dict(signatures).encode()
}

fn gpg_sigs_dict(signatures: &[Vec<u8>]) -> Value {
    Value::dict(vec![Value::entry(
        "ostree.gpgsigs",
        Value::Array(
            Ty::parse("ay").expect("static type"),
            signatures.iter().cloned().map(Value::Bytes).collect(),
        ),
    )])
}

/// The repository `config` clients read to learn its mode.
pub fn render_config() -> String {
    "[core]\nrepo_version=1\nmode=archive-z2\n".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ostree::gvariant::View;

    fn sample() -> Vec<SummaryRef> {
        vec![
            SummaryRef {
                name: "app/org.example.Zed/x86_64/stable".into(),
                commit: Checksum([2; 32]),
                commit_size: 600,
                timestamp: 1_700_000_000,
                installed_size: 4096,
                download_size: 1024,
                metadata: "[Application]\nname=org.example.Zed\n".into(),
            },
            SummaryRef {
                name: "app/org.example.Alpha/x86_64/stable".into(),
                commit: Checksum([1; 32]),
                commit_size: 500,
                timestamp: 1_600_000_000,
                installed_size: 2048,
                download_size: 512,
                metadata: "[Application]\nname=org.example.Alpha\n".into(),
            },
        ]
    }

    #[test]
    fn the_summary_lists_refs_sorted_with_their_commits() {
        let bytes = render_summary(&sample(), 1_700_000_001);
        let view = View::new("(a(s(taya{sv}))a{sv})", &bytes).unwrap();
        let refs = view.child(0).unwrap();
        assert_eq!(refs.len().unwrap(), 2);
        let first = refs.at(0).unwrap();
        assert_eq!(
            first.child(0).unwrap().as_str().unwrap(),
            "app/org.example.Alpha/x86_64/stable"
        );
        let detail = first.child(1).unwrap();
        assert_eq!(detail.child(0).unwrap().as_u64().unwrap(), 500);
        assert_eq!(
            detail.child(1).unwrap().as_byte_array().unwrap(),
            &[1u8; 32]
        );
        let ts = detail
            .child(2)
            .unwrap()
            .dict_get("ostree.commit.timestamp")
            .unwrap()
            .unwrap()
            .as_u64()
            .unwrap();
        assert_eq!(ts.swap_bytes(), 1_600_000_000);
    }

    #[test]
    fn the_summary_carries_flatpaks_cache() {
        let bytes = render_summary(&sample(), 0);
        let view = View::new("(a(s(taya{sv}))a{sv})", &bytes).unwrap();
        let cache = view
            .child(1)
            .unwrap()
            .dict_get("xa.cache")
            .unwrap()
            .expect("xa.cache is present")
            .variant()
            .expect("xa.cache is a variant inside its variant");
        assert_eq!(cache.ty().signature(), "a{s(tts)}");
        let entry = cache.at(0).unwrap();
        assert_eq!(
            entry.child(0).unwrap().as_str().unwrap(),
            "app/org.example.Alpha/x86_64/stable"
        );
        let sizes = entry.child(1).unwrap();
        assert_eq!(sizes.child(0).unwrap().as_u64().unwrap().swap_bytes(), 2048);
        assert_eq!(sizes.child(1).unwrap().as_u64().unwrap().swap_bytes(), 512);
        assert!(sizes
            .child(2)
            .unwrap()
            .as_str()
            .unwrap()
            .contains("org.example.Alpha"));
    }

    /// A summary `ostree` and `flatpak build-update-repo` wrote, for the
    /// app in `tests/fixtures/hello.flatpak`.
    const REAL: &[u8] = include_bytes!("../../tests/fixtures/hello.summary");

    fn hello_ref() -> SummaryRef {
        SummaryRef {
            name: "app/org.example.Hello/x86_64/stable".into(),
            commit: Checksum::from_hex(
                "6bff8a2710a3eb3d2124d3804230e388836e089e9e4761293f6c0d160e38151e",
            )
            .unwrap(),
            commit_size: 596,
            timestamp: 1_790_000_872,
            installed_size: 1024,
            download_size: 192,
            metadata: "[Application]\nname=org.example.Hello\nruntime=org.freedesktop.Platform/x86_64/24.08\nsdk=org.freedesktop.Sdk/x86_64/24.08\ncommand=hello\n".into(),
        }
    }

    #[test]
    fn the_summary_agrees_with_one_a_real_repository_wrote() {
        let real = View::new("(a(s(taya{sv}))a{sv})", REAL).unwrap();
        let real_ref = real.child(0).unwrap().at(0).unwrap();
        let real_detail = real_ref.child(1).unwrap();
        let real_timestamp = real_detail
            .child(2)
            .unwrap()
            .dict_get("ostree.commit.timestamp")
            .unwrap()
            .unwrap()
            .as_u64()
            .unwrap()
            .swap_bytes();

        let mut ours_ref = hello_ref();
        ours_ref.timestamp = real_timestamp;
        let ours_bytes = render_summary(&[ours_ref], 0);
        let ours = View::new("(a(s(taya{sv}))a{sv})", &ours_bytes).unwrap();
        let our_ref = ours.child(0).unwrap().at(0).unwrap();

        // The ref entry is byte-for-byte what OSTree wrote: name, commit
        // size and checksum, and the timestamp dictionary.
        assert_eq!(our_ref.bytes(), real_ref.bytes());

        // And every repository-level key a real summary has, except the
        // ones that describe deltas this server does not publish, carries
        // the same value.
        let real_meta = real.child(1).unwrap();
        let our_meta = ours.child(1).unwrap();
        for key in [
            "ostree.summary.mode",
            "ostree.summary.tombstone-commits",
            "xa.cache-version",
            "xa.cache",
            "xa.sparse-cache",
        ] {
            let a = real_meta
                .dict_get(key)
                .unwrap()
                .unwrap_or_else(|| panic!("{key} (real)"));
            let b = our_meta
                .dict_get(key)
                .unwrap()
                .unwrap_or_else(|| panic!("{key} (ours)"));
            assert_eq!(a.ty(), b.ty(), "{key}");
            assert_eq!(a.bytes(), b.bytes(), "{key}");
        }
    }

    #[test]
    fn an_empty_repository_still_has_a_valid_summary() {
        let bytes = render_summary(&[], 0);
        let view = View::new("(a(s(taya{sv}))a{sv})", &bytes).unwrap();
        assert_eq!(view.child(0).unwrap().len().unwrap(), 0);
    }

    #[test]
    fn signature_files_hold_each_signature() {
        let bytes = render_signature_file(&[vec![1, 2, 3], vec![4, 5]]);
        let view = View::new("a{sv}", &bytes).unwrap();
        let sigs = view.dict_get("ostree.gpgsigs").unwrap().unwrap();
        assert_eq!(sigs.ty().signature(), "aay");
        assert_eq!(sigs.len().unwrap(), 2);
        assert_eq!(sigs.at(1).unwrap().as_byte_array().unwrap(), &[4, 5]);
    }

    #[test]
    fn the_config_declares_an_archive_repository() {
        let config = render_config();
        assert!(config.contains("mode=archive-z2"));
        assert!(config.contains("repo_version=1"));
    }
}
