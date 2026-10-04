//! Static-delta replay: turns a Flatpak bundle into verified objects.
//!
//! A `.flatpak` file is an OSTree static-delta *superblock* generated
//! against nothing, with its parts embedded in the superblock's own
//! metadata dictionary:
//!
//! ```text
//! (a{sv} t ay ay (commit) ay a(uayttay) a(yaytt))
//!   meta  ts from to  commit deps parts  fallbacks
//! ```
//!
//! `meta` carries the Flatpak keys (`ref`, `metadata`, `collection-id`) and
//! one `deltas/…/N` entry per part; each part is `(yay)`, a compression
//! byte (`0` none, `x` xz) and the payload. A decompressed part is
//!
//! ```text
//! (a(uuu) aa(ayay) ay ay)
//!   modes  xattrs  data ops
//! ```
//!
//! and its ops are a little program that builds objects out of the data:
//! `S` writes a whole object, `o`/`w`/`c` stream a large file in pieces.
//! Operands are unsigned LEB128 varints. The part's object table, in the
//! superblock, names each object the ops produce, in order, by type and
//! checksum.
//!
//! The ops `r` (read an existing object) and `B` (bspatch against one)
//! reference a parent that a from-scratch delta does not have, so they are
//! refused. Every object's checksum is recomputed from the bytes the ops
//! produced and compared with the table; a bundle cannot smuggle in an
//! object under a name that isn't its own.

use super::gvariant::{Error, View};
use super::object::{
    file_checksum, metadata_checksum, validate_dirmeta, Checksum, Commit, DirTree, FileMeta,
    ObjType, CHECKSUM_LEN,
};
use crate::{inflate_capped, MAX_INFLATED_BYTES};

type Result<T> = std::result::Result<T, Error>;

const SUPERBLOCK_TYPE: &str = "(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))";
const PART_TYPE: &str = "(a(uuu)aa(ayay)ayay)";

/// The most objects one bundle may define.
///
/// Objects are held in memory until they are stored, and each costs more
/// than its content, so the count is bounded alongside the byte total.
pub const MAX_OBJECTS: usize = 1_000_000;

/// An object table entry: type byte plus checksum.
const TABLE_ENTRY_LEN: usize = 1 + CHECKSUM_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Metadata(Vec<u8>),
    File { meta: FileMeta, content: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub ty: ObjType,
    pub checksum: Checksum,
    pub body: Body,
}

/// A bundle, opened and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// `app/org.example.Hello/x86_64/stable`.
    pub reference: String,
    /// The app's `metadata` keyfile, when the bundle carries one.
    pub metadata: Option<String>,
    pub commit_checksum: Checksum,
    /// The commit object's serialised bytes.
    pub commit: Vec<u8>,
    /// Every object the commit's tree needs, commit included.
    pub objects: Vec<Object>,
}

/// Opens a bundle: parses the superblock, replays every part, and checks
/// each object against its name.
pub fn read_bundle(bytes: &[u8]) -> Result<Bundle> {
    read_bundle_limited(bytes, MAX_INFLATED_BYTES)
}

/// [`read_bundle`] with the inflation budget as a parameter, so a test can
/// exercise the limit without allocating gigabytes.
pub(crate) fn read_bundle_limited(bytes: &[u8], inflate_limit: u64) -> Result<Bundle> {
    let view = View::new(SUPERBLOCK_TYPE, bytes)?;
    let meta = view.child(0)?;

    let reference = meta
        .dict_get("ref")?
        .ok_or_else(|| Error("bundle has no ref".into()))?
        .as_str()?
        .to_string();
    validate_ref(&reference)?;
    let metadata = match meta.dict_get("metadata")? {
        Some(v) => Some(v.as_str()?.to_string()),
        None => None,
    };
    if let Some(endianness) = meta.dict_get("ostree.endianness")? {
        if endianness.as_u8()? != b'l' {
            return Err(Error("big-endian bundles are not supported".into()));
        }
    }

    // Bundles are generated against nothing; a delta with a source has
    // parts that depend on objects this server does not hold.
    if !view.child(2)?.as_byte_array()?.is_empty() {
        return Err(Error(
            "bundle is an incremental delta, not a full export".into(),
        ));
    }
    if !view.child(5)?.is_empty()? {
        return Err(Error("bundle depends on other deltas".into()));
    }
    if !view.child(7)?.is_empty()? {
        return Err(Error("bundle has fallback objects".into()));
    }

    let to = Checksum::from_slice(view.child(3)?.as_byte_array()?)?;
    let commit_bytes = view.child(4)?.bytes().to_vec();
    if metadata_checksum(&commit_bytes) != to {
        return Err(Error(
            "the bundle's commit does not match its checksum".into(),
        ));
    }
    let commit = Commit::parse(&commit_bytes)?;
    check_ref_binding(&commit_bytes, &reference)?;

    let mut objects = Vec::new();
    let mut budget = inflate_limit;

    let parts = view.child(6)?;
    for index in 0..parts.len()? {
        let entry = parts.at(index)?;
        let table = entry.child(4)?.as_byte_array()?;
        let inline = meta
            .dict_get(&inline_key(&meta, index)?)?
            .ok_or_else(|| Error(format!("bundle part {index} is missing")))?;

        let raw = decompress_part(&inline, &mut budget)?;
        replay_part(&raw, table, &mut objects, &mut budget)?;
    }

    objects.push(Object {
        ty: ObjType::Commit,
        checksum: to,
        body: Body::Metadata(commit_bytes.clone()),
    });

    // The root the commit names must be among what was imported.
    for (ty, sum) in [
        (ObjType::DirTree, commit.root_tree),
        (ObjType::DirMeta, commit.root_meta),
    ] {
        if !objects.iter().any(|o| o.ty == ty && o.checksum == sum) {
            return Err(Error(format!(
                "bundle lacks the commit's root {ty:?} {sum}"
            )));
        }
    }

    Ok(Bundle {
        reference,
        metadata,
        commit_checksum: to,
        commit: commit_bytes,
        objects,
    })
}

/// Finds the metadata key holding part `index`: `deltas/<name>/<index>`.
fn inline_key(meta: &View<'_>, index: usize) -> Result<String> {
    let suffix = format!("/{index}");
    let mut found = None;
    for entry in meta.iter()? {
        let key = entry?.child(0)?.as_str()?.to_string();
        if key.starts_with("deltas/") && key.ends_with(&suffix) {
            if found.is_some() {
                return Err(Error(format!("bundle part {index} is ambiguous")));
            }
            found = Some(key);
        }
    }
    found.ok_or_else(|| Error(format!("bundle part {index} is missing")))
}

/// Accepts `app/<id>/<arch>/<branch>` and `runtime/<id>/<arch>/<branch>`.
///
/// The ref names a path in the served tree and a row in the database, so
/// each component is held to a conservative alphabet.
pub fn validate_ref(reference: &str) -> Result<()> {
    let parts: Vec<&str> = reference.split('/').collect();
    let [kind, id, arch, branch] = parts.as_slice() else {
        return Err(Error(format!("{reference:?} is not a flatpak ref")));
    };
    if *kind != "app" && *kind != "runtime" {
        return Err(Error(format!(
            "{reference:?} is neither an app nor a runtime"
        )));
    }
    for (what, part) in [("id", id), ("arch", arch), ("branch", branch)] {
        let ok = !part.is_empty()
            && !part.starts_with('.')
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'));
        if !ok {
            return Err(Error(format!("invalid {what} {part:?} in ref")));
        }
    }
    Ok(())
}

/// A commit that binds itself to refs may only be published as one of
/// them; otherwise a signed commit for one app could be republished
/// under another's name.
pub fn check_ref_binding(commit: &[u8], reference: &str) -> Result<()> {
    let meta = Commit::metadata(commit)?;
    let Some(binding) = meta.dict_get("ostree.ref-binding")? else {
        return Ok(());
    };
    for item in binding.iter()? {
        if item?.as_str()? == reference {
            return Ok(());
        }
    }
    Err(Error(format!(
        "the commit is bound to other refs, not {reference}"
    )))
}

fn decompress_part(inline: &View<'_>, budget: &mut u64) -> Result<Vec<u8>> {
    let compression = inline.child(0)?.as_u8()?;
    let data = inline.child(1)?.as_byte_array()?;
    let out = match compression {
        0 => {
            if data.len() as u64 > *budget {
                return Err(Error("bundle exceeds the decompression limit".into()));
            }
            data.to_vec()
        }
        b'x' => inflate_capped(liblzma::read::XzDecoder::new(data), *budget, "bundle part")
            .map_err(|e| Error(e.to_string()))?,
        other => return Err(Error(format!("unknown part compression {other:#x}"))),
    };
    *budget -= out.len() as u64;
    Ok(out)
}

struct OpenFile {
    meta: FileMeta,
    size: u64,
    checksum: Checksum,
    content: Vec<u8>,
}

fn replay_part(raw: &[u8], table: &[u8], out: &mut Vec<Object>, budget: &mut u64) -> Result<()> {
    if !table.len().is_multiple_of(TABLE_ENTRY_LEN) {
        return Err(Error(
            "object table is not a whole number of entries".into(),
        ));
    }
    let count = table.len() / TABLE_ENTRY_LEN;
    if count == 0 {
        return Ok(());
    }
    if out.len().saturating_add(count) > MAX_OBJECTS {
        return Err(Error(format!(
            "bundle defines more than {MAX_OBJECTS} objects"
        )));
    }

    let part = View::new(PART_TYPE, raw)?;
    let modes = part.child(0)?;
    let xattrs = part.child(1)?;
    let data = part.child(2)?.as_byte_array()?;
    let ops = part.child(3)?.as_byte_array()?;

    let mut cursor = Cursor { ops, pos: 0 };
    let mut next = 0usize;
    let mut open: Option<OpenFile> = None;

    // The object an op is about to produce.
    let target = |next: &mut usize| -> Result<(ObjType, Checksum)> {
        if *next >= count {
            return Err(Error("ops define more objects than the table lists".into()));
        }
        let entry = &table[*next * TABLE_ENTRY_LEN..(*next + 1) * TABLE_ENTRY_LEN];
        *next += 1;
        Ok((
            ObjType::from_byte(entry[0])?,
            Checksum::from_slice(&entry[1..])?,
        ))
    };

    while let Some(opcode) = cursor.opcode() {
        match opcode {
            b'S' => {
                if open.is_some() {
                    return Err(Error("a new object starts inside an open one".into()));
                }
                let (ty, expected) = target(&mut next)?;
                if ty.is_metadata() {
                    let length = cursor.varint()?;
                    let offset = cursor.varint()?;
                    let bytes = slice(data, offset, length)?.to_vec();
                    charge(budget, length)?;
                    verify_metadata(ty, &bytes, expected)?;
                    out.push(Object {
                        ty,
                        checksum: expected,
                        body: Body::Metadata(bytes),
                    });
                } else {
                    let mode_index = cursor.varint()?;
                    let xattr_index = cursor.varint()?;
                    let size = cursor.varint()?;
                    let offset = cursor.varint()?;
                    let payload = slice(data, offset, size)?;
                    let mut meta = file_meta(&modes, &xattrs, mode_index, xattr_index)?;
                    let content = if meta.is_symlink() {
                        meta.symlink_target = std::str::from_utf8(payload)
                            .map_err(|_| Error("symlink target is not UTF-8".into()))?
                            .to_string();
                        meta.validate()?;
                        Vec::new()
                    } else {
                        payload.to_vec()
                    };
                    charge(budget, size)?;
                    let sum = file_checksum(&meta, &content);
                    if sum != expected {
                        return Err(Error(format!(
                            "file object {expected} does not match its content"
                        )));
                    }
                    out.push(Object {
                        ty,
                        checksum: expected,
                        body: Body::File { meta, content },
                    });
                }
            }
            b'o' => {
                if open.is_some() {
                    return Err(Error("a file is opened while another is open".into()));
                }
                let (ty, expected) = target(&mut next)?;
                if ty != ObjType::File {
                    return Err(Error("only a file can be streamed".into()));
                }
                let mode_index = cursor.varint()?;
                let xattr_index = cursor.varint()?;
                let size = cursor.varint()?;
                let meta = file_meta(&modes, &xattrs, mode_index, xattr_index)?;
                if !meta.is_regular() {
                    return Err(Error("only a regular file can be streamed".into()));
                }
                charge(budget, size)?;
                open = Some(OpenFile {
                    meta,
                    size,
                    checksum: expected,
                    content: Vec::new(),
                });
            }
            b'w' => {
                let Some(file) = open.as_mut() else {
                    return Err(Error("a write with no open file".into()));
                };
                let size = cursor.varint()?;
                let offset = cursor.varint()?;
                let piece = slice(data, offset, size)?;
                if file.content.len() as u64 + size > file.size {
                    return Err(Error("a file is written past its declared size".into()));
                }
                file.content.extend_from_slice(piece);
            }
            b'c' => {
                let Some(file) = open.take() else {
                    return Err(Error("a close with no open file".into()));
                };
                if file.content.len() as u64 != file.size {
                    return Err(Error("a file is closed short of its declared size".into()));
                }
                if file_checksum(&file.meta, &file.content) != file.checksum {
                    return Err(Error(format!(
                        "file object {} does not match its content",
                        file.checksum
                    )));
                }
                out.push(Object {
                    ty: ObjType::File,
                    checksum: file.checksum,
                    body: Body::File {
                        meta: file.meta,
                        content: file.content,
                    },
                });
            }
            b'R' => {}
            b'r' | b'B' => {
                return Err(Error(
                    "the bundle patches an object it does not carry".into(),
                ))
            }
            other => return Err(Error(format!("unknown delta opcode {other:#x}"))),
        }
    }

    if open.is_some() {
        return Err(Error("a part ends with a file still open".into()));
    }
    if next != count {
        return Err(Error(
            "a part defines fewer objects than its table lists".into(),
        ));
    }
    Ok(())
}

fn charge(budget: &mut u64, bytes: u64) -> Result<()> {
    *budget = budget
        .checked_sub(bytes)
        .ok_or_else(|| Error("bundle exceeds the decompression limit".into()))?;
    Ok(())
}

fn slice(data: &[u8], offset: u64, length: u64) -> Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error("part offset overflows".into()))?;
    if end > data.len() as u64 {
        return Err(Error("part offset lies outside its data".into()));
    }
    Ok(&data[offset as usize..end as usize])
}

fn file_meta(modes: &View<'_>, xattrs: &View<'_>, mode: u64, xattr: u64) -> Result<FileMeta> {
    let mode = usize::try_from(mode).map_err(|_| Error("mode index out of range".into()))?;
    let xattr = usize::try_from(xattr).map_err(|_| Error("xattr index out of range".into()))?;
    if mode >= modes.len()? {
        return Err(Error("mode index out of range".into()));
    }
    if xattr >= xattrs.len()? {
        return Err(Error("xattr index out of range".into()));
    }
    let entry = modes.at(mode)?;
    let meta = FileMeta {
        uid: entry.child(0)?.as_u32()?.swap_bytes(),
        gid: entry.child(1)?.as_u32()?.swap_bytes(),
        mode: entry.child(2)?.as_u32()?.swap_bytes(),
        symlink_target: String::new(),
        xattrs: xattrs.at(xattr)?.bytes().to_vec(),
    };
    Ok(meta)
}

/// Checks a metadata object is well-formed and named by its checksum.
pub fn verify_metadata(ty: ObjType, bytes: &[u8], expected: Checksum) -> Result<()> {
    if metadata_checksum(bytes) != expected {
        return Err(Error(format!(
            "{ty:?} object {expected} does not match its content"
        )));
    }
    match ty {
        ObjType::DirTree => DirTree::parse(bytes).map(|_| ()),
        ObjType::DirMeta => validate_dirmeta(bytes),
        ObjType::Commit => Commit::parse(bytes).map(|_| ()),
        ObjType::File => Err(Error("a file is not a metadata object".into())),
    }
}

struct Cursor<'a> {
    ops: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn opcode(&mut self) -> Option<u8> {
        let b = *self.ops.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// Unsigned LEB128.
    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let Some(&byte) = self.ops.get(self.pos) else {
                return Err(Error("a delta op ends mid-operand".into()));
            };
            self.pos += 1;
            if shift >= 64 || (shift == 63 && byte & 0x7e != 0) {
                return Err(Error("a delta operand overflows 64 bits".into()));
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &[u8] = include_bytes!("../../tests/fixtures/hello.flatpak");

    #[test]
    fn a_real_bundle_replays_into_verified_objects() {
        let bundle = read_bundle(HELLO).unwrap();
        assert_eq!(bundle.reference, "app/org.example.Hello/x86_64/stable");
        assert_eq!(
            bundle.commit_checksum.hex(),
            "6bff8a2710a3eb3d2124d3804230e388836e089e9e4761293f6c0d160e38151e"
        );
        // Seven objects from the part, plus the commit.
        assert_eq!(bundle.objects.len(), 8);
        let files: Vec<_> = bundle
            .objects
            .iter()
            .filter(|o| o.ty == ObjType::File)
            .collect();
        assert_eq!(files.len(), 2);
        assert!(bundle
            .metadata
            .as_deref()
            .unwrap()
            .contains("name=org.example.Hello"));
        let script = files
            .iter()
            .find_map(|o| match &o.body {
                Body::File { content, .. } if content.starts_with(b"#!/bin/sh") => Some(content),
                _ => None,
            })
            .expect("the script is in the bundle");
        assert_eq!(script, b"#!/bin/sh\necho hello\n");
    }

    #[test]
    fn a_corrupted_object_is_rejected() {
        let mut bytes = HELLO.to_vec();
        // Flip a byte in the xz stream's tail: either decompression or an
        // object checksum must fail, and neither may panic.
        let at = bytes.len() / 2;
        bytes[at] ^= 0xff;
        assert!(read_bundle(&bytes).is_err());
    }

    #[test]
    fn a_truncated_bundle_is_rejected() {
        for cut in [0, 8, 100, HELLO.len() / 2, HELLO.len() - 1] {
            assert!(read_bundle(&HELLO[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn the_inflation_budget_is_enforced() {
        let err = read_bundle_limited(HELLO, 64).unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
    }

    #[test]
    fn refs_are_held_to_a_safe_alphabet() {
        assert!(validate_ref("app/org.example.Hello/x86_64/stable").is_ok());
        assert!(validate_ref("runtime/org.example.Platform/aarch64/24.08").is_ok());
        for bad in [
            "",
            "app/x/y",
            "app/../x86_64/stable",
            "app/org.example.Hello/x86_64/",
            "other/org.example.Hello/x86_64/stable",
            "app/org.example.Hello/x86_64/sta ble",
            "app/org.example.Hello/x86_64/.hidden",
            "app/org.example.Hello/x86_64/stable/extra",
        ] {
            assert!(validate_ref(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn varints_decode_and_reject_overflow() {
        let mut c = Cursor {
            ops: &[0xbf, 0x01, 0x48],
            pos: 0,
        };
        assert_eq!(c.varint().unwrap(), 191);
        assert_eq!(c.varint().unwrap(), 72);
        let mut overlong = Cursor {
            ops: &[0xff; 11],
            pos: 0,
        };
        assert!(overlong.varint().is_err());
        let mut truncated = Cursor {
            ops: &[0x80],
            pos: 0,
        };
        assert!(truncated.varint().is_err());
    }

    /// Bundles built by hand, so each malformed shape can be had exactly.
    ///
    /// Real bundles only ever hold well-formed deltas; the replayer's job
    /// is the other kind, so these assemble a superblock from parts and
    /// let a test break one thing at a time.
    mod synthetic {
        use super::*;
        use crate::ostree::gvariant::{Ty, Value};
        use std::io::Write;

        const REF: &str = "app/org.example.Synth/x86_64/stable";

        fn varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    return out;
                }
                out.push(byte | 0x80);
            }
        }

        fn ty(s: &str) -> Ty {
            Ty::parse(s).unwrap()
        }

        fn empty_tree() -> Vec<u8> {
            Value::Tuple(vec![
                Value::Array(ty("(say)"), vec![]),
                Value::Array(ty("(sayay)"), vec![]),
            ])
            .encode()
        }

        fn dirmeta() -> Vec<u8> {
            Value::Tuple(vec![
                Value::U32(0),
                Value::U32(0),
                Value::U32(0o040755u32.swap_bytes()),
                Value::Array(ty("(ayay)"), vec![]),
            ])
            .encode()
        }

        fn commit(tree: &[u8], meta: &[u8], bindings: Option<&[&str]>) -> Vec<u8> {
            let mut entries = vec![Value::entry("xa.ref", Value::str(REF))];
            if let Some(refs) = bindings {
                entries.push(Value::entry(
                    "ostree.ref-binding",
                    Value::Array(ty("s"), refs.iter().map(|r| Value::str(*r)).collect()),
                ));
            }
            Value::Tuple(vec![
                Value::dict(entries),
                Value::Bytes(vec![]),
                Value::Array(ty("(say)"), vec![]),
                Value::str("synthetic"),
                Value::str(""),
                Value::U64(1_700_000_000u64.swap_bytes()),
                Value::Bytes(metadata_checksum(tree).0.to_vec()),
                Value::Bytes(metadata_checksum(meta).0.to_vec()),
            ])
            .encode()
        }

        /// What a test varies. `Default` is a valid two-object bundle.
        pub struct Spec {
            pub reference: String,
            pub compression: u8,
            pub from: Vec<u8>,
            pub deps: bool,
            pub fallback: bool,
            pub endianness: u8,
            pub bindings: Option<Vec<String>>,
            pub wrong_to: bool,
            /// Appended to the part's payload, after the two metadata objects.
            pub extra_data: Vec<u8>,
            /// Appended to the ops after the two `S` ops.
            pub extra_ops: Vec<u8>,
            /// Table entries appended after the two metadata objects.
            pub extra_table: Vec<(u8, Checksum)>,
            /// Replaces the table's byte form outright when set.
            pub raw_table: Option<Vec<u8>>,
            pub modes: Vec<(u32, u32, u32)>,
            pub xattr_sets: usize,
            pub tamper_tree: bool,
            pub drop_part: bool,
            pub omit_ref: bool,
            pub omit_root_tree: bool,
        }

        impl Default for Spec {
            fn default() -> Self {
                Spec {
                    reference: REF.to_string(),
                    compression: 0,
                    from: vec![],
                    deps: false,
                    fallback: false,
                    endianness: b'l',
                    bindings: None,
                    wrong_to: false,
                    extra_data: vec![],
                    extra_ops: vec![],
                    extra_table: vec![],
                    raw_table: None,
                    modes: vec![(0, 0, 0o100644u32.swap_bytes())],
                    xattr_sets: 1,
                    tamper_tree: false,
                    drop_part: false,
                    omit_ref: false,
                    omit_root_tree: false,
                }
            }
        }

        pub fn build(spec: &Spec) -> Vec<u8> {
            let tree = empty_tree();
            let meta = dirmeta();
            let binding_refs: Option<Vec<&str>> = spec
                .bindings
                .as_ref()
                .map(|b| b.iter().map(String::as_str).collect());
            let commit_bytes = commit(&tree, &meta, binding_refs.as_deref());

            let mut data = meta.clone();
            data.extend_from_slice(&tree);
            data.extend_from_slice(&spec.extra_data);
            if spec.tamper_tree {
                let at = meta.len();
                data[at] ^= 0xff;
            }
            let mut ops = vec![b'S'];
            ops.extend(varint(meta.len() as u64));
            ops.extend(varint(0));
            ops.push(b'S');
            ops.extend(varint(tree.len() as u64));
            ops.extend(varint(meta.len() as u64));
            ops.extend_from_slice(&spec.extra_ops);

            let mut table = Vec::new();
            table.push(3u8);
            table.extend_from_slice(&metadata_checksum(&meta).0);
            table.push(2u8);
            if spec.omit_root_tree {
                table.extend_from_slice(&[9u8; 32]);
            } else {
                table.extend_from_slice(&metadata_checksum(&tree).0);
            }
            for (t, c) in &spec.extra_table {
                table.push(*t);
                table.extend_from_slice(&c.0);
            }
            if let Some(raw) = &spec.raw_table {
                table = raw.clone();
            }

            let xattrs = Value::Array(
                ty("a(ayay)"),
                (0..spec.xattr_sets)
                    .map(|_| Value::Array(ty("(ayay)"), vec![]))
                    .collect(),
            );
            let modes = Value::Array(
                ty("(uuu)"),
                spec.modes
                    .iter()
                    .map(|(u, g, m)| {
                        Value::Tuple(vec![Value::U32(*u), Value::U32(*g), Value::U32(*m)])
                    })
                    .collect(),
            );
            let part =
                Value::Tuple(vec![modes, xattrs, Value::Bytes(data), Value::Bytes(ops)]).encode();

            let stored = match spec.compression {
                b'x' => {
                    let mut enc = liblzma::write::XzEncoder::new(Vec::new(), 6);
                    enc.write_all(&part).unwrap();
                    enc.finish().unwrap()
                }
                _ => part.clone(),
            };

            let mut meta_entries = vec![
                Value::entry("flatpak", Value::U32(0xe5890001)),
                Value::entry(
                    "metadata",
                    Value::str("[Application]\nname=org.example.Synth\n"),
                ),
                Value::entry("ostree.endianness", Value::Byte(spec.endianness)),
            ];
            if !spec.omit_ref {
                meta_entries.push(Value::entry("ref", Value::str(&spec.reference)));
            }
            if !spec.drop_part {
                meta_entries.push(Value::entry(
                    "deltas/aa/bbb/0",
                    Value::Tuple(vec![Value::Byte(spec.compression), Value::Bytes(stored)]),
                ));
            }

            let to = if spec.wrong_to {
                Checksum([0xee; 32])
            } else {
                metadata_checksum(&commit_bytes)
            };
            let entry = Value::Tuple(vec![
                Value::U32(0),
                Value::Bytes(vec![0; 32]),
                Value::U64(0),
                Value::U64(0),
                Value::Bytes(table),
            ]);
            let fallback_entry = Value::Tuple(vec![
                Value::Byte(1),
                Value::Bytes(vec![0; 32]),
                Value::U64(0),
                Value::U64(0),
            ]);
            Value::Tuple(vec![
                Value::dict(meta_entries),
                Value::U64(0),
                Value::Bytes(spec.from.clone()),
                Value::Bytes(to.0.to_vec()),
                Value::Raw(ty(COMMIT_TYPE_STR), commit_bytes),
                Value::Bytes(if spec.deps { vec![1; 32] } else { vec![] }),
                Value::Array(ty("(uayttay)"), vec![entry]),
                Value::Array(
                    ty("(yaytt)"),
                    if spec.fallback {
                        vec![fallback_entry]
                    } else {
                        vec![]
                    },
                ),
            ])
            .encode()
        }

        const COMMIT_TYPE_STR: &str = "(a{sv}aya(say)sstayay)";

        fn err_of(spec: Spec) -> String {
            read_bundle(&build(&spec)).unwrap_err().to_string()
        }

        fn file_object(content: &[u8], mode: u32, target: &str) -> (Checksum, FileMeta) {
            let meta = FileMeta {
                uid: 0,
                gid: 0,
                mode,
                symlink_target: target.to_string(),
                xattrs: Vec::new(),
            };
            let content = if meta.is_symlink() { &[][..] } else { content };
            (file_checksum(&meta, content), meta)
        }

        /// `S` op for a file whose payload sits at `offset`.
        fn s_file(mode_idx: u64, size: u64, offset: u64) -> Vec<u8> {
            let mut v = vec![b'S'];
            v.extend(varint(mode_idx));
            v.extend(varint(0));
            v.extend(varint(size));
            v.extend(varint(offset));
            v
        }

        fn base_len() -> u64 {
            (dirmeta().len() + empty_tree().len()) as u64
        }

        #[test]
        fn the_synthetic_baseline_is_a_valid_bundle() {
            let bundle = read_bundle(&build(&Spec::default())).unwrap();
            assert_eq!(bundle.reference, REF);
            assert_eq!(bundle.objects.len(), 3, "dirmeta, dirtree, commit");
            assert_eq!(
                bundle.metadata.as_deref(),
                Some("[Application]\nname=org.example.Synth\n")
            );
        }

        #[test]
        fn an_xz_compressed_part_is_inflated() {
            let bundle = read_bundle(&build(&Spec {
                compression: b'x',
                ..Spec::default()
            }))
            .unwrap();
            assert_eq!(bundle.objects.len(), 3);
        }

        #[test]
        fn an_unknown_part_compression_is_refused() {
            let err = err_of(Spec {
                compression: b'z',
                ..Spec::default()
            });
            assert!(err.contains("compression"), "{err}");
        }

        #[test]
        fn an_incremental_delta_is_refused() {
            let err = err_of(Spec {
                from: vec![1; 32],
                ..Spec::default()
            });
            assert!(err.contains("incremental"), "{err}");
        }

        #[test]
        fn a_delta_that_depends_on_other_deltas_is_refused() {
            let err = err_of(Spec {
                deps: true,
                ..Spec::default()
            });
            assert!(err.contains("depends"), "{err}");
        }

        #[test]
        fn a_delta_with_fallback_objects_is_refused() {
            let err = err_of(Spec {
                fallback: true,
                ..Spec::default()
            });
            assert!(err.contains("fallback"), "{err}");
        }

        #[test]
        fn a_big_endian_bundle_is_refused() {
            let err = err_of(Spec {
                endianness: b'B',
                ..Spec::default()
            });
            assert!(err.contains("big-endian"), "{err}");
        }

        #[test]
        fn a_bundle_without_a_ref_or_with_a_bad_one_is_refused() {
            assert!(err_of(Spec {
                omit_ref: true,
                ..Spec::default()
            })
            .contains("no ref"));
            assert!(err_of(Spec {
                reference: "app/../x86_64/stable".into(),
                ..Spec::default()
            })
            .contains("invalid"));
        }

        #[test]
        fn a_commit_that_does_not_match_its_checksum_is_refused() {
            let err = err_of(Spec {
                wrong_to: true,
                ..Spec::default()
            });
            assert!(err.contains("commit does not match"), "{err}");
        }

        #[test]
        fn a_tampered_metadata_object_is_refused() {
            let err = err_of(Spec {
                tamper_tree: true,
                ..Spec::default()
            });
            assert!(err.contains("does not match its content"), "{err}");
        }

        #[test]
        fn a_missing_part_is_refused() {
            let err = err_of(Spec {
                drop_part: true,
                ..Spec::default()
            });
            assert!(err.contains("part 0 is missing"), "{err}");
        }

        #[test]
        fn a_commit_whose_root_is_absent_is_refused() {
            let err = err_of(Spec {
                omit_root_tree: true,
                ..Spec::default()
            });
            assert!(
                err.contains("does not match") || err.contains("lacks"),
                "{err}"
            );
        }

        #[test]
        fn a_commit_bound_to_other_refs_is_refused_and_one_bound_to_this_ref_is_not() {
            let err = err_of(Spec {
                bindings: Some(vec!["app/org.example.Other/x86_64/stable".into()]),
                ..Spec::default()
            });
            assert!(err.contains("bound to other refs"), "{err}");

            read_bundle(&build(&Spec {
                bindings: Some(vec![
                    "app/org.example.Other/x86_64/stable".into(),
                    REF.into(),
                ]),
                ..Spec::default()
            }))
            .expect("a binding that includes the ref is fine");
        }

        #[test]
        fn a_symlink_is_replayed_with_its_target() {
            let (sum, _) = file_object(b"", 0o120777, "../elsewhere");
            let target = b"../elsewhere";
            let data = target.to_vec();
            let bundle = read_bundle(&build(&Spec {
                modes: vec![(0, 0, 0o120777u32.swap_bytes())],
                extra_data: data,
                extra_ops: s_file(0, target.len() as u64, base_len()),
                extra_table: vec![(1, sum)],
                ..Spec::default()
            }))
            .unwrap();
            let link = bundle
                .objects
                .iter()
                .find(|o| o.ty == ObjType::File)
                .expect("the symlink");
            match &link.body {
                Body::File { meta, content } => {
                    assert_eq!(meta.symlink_target, "../elsewhere");
                    assert!(content.is_empty());
                }
                other => panic!("{other:?}"),
            }
        }

        #[test]
        fn a_symlink_target_that_is_not_utf8_is_refused() {
            let (sum, _) = file_object(b"", 0o120777, "x");
            let err = err_of(Spec {
                modes: vec![(0, 0, 0o120777u32.swap_bytes())],
                extra_data: vec![0xff, 0xfe],
                extra_ops: s_file(0, 2, base_len()),
                extra_table: vec![(1, sum)],
                ..Spec::default()
            });
            assert!(err.contains("UTF-8"), "{err}");
        }

        #[test]
        fn a_device_node_in_a_part_is_refused() {
            let (sum, _) = file_object(b"x", 0o100644, "");
            let err = err_of(Spec {
                modes: vec![(0, 0, 0o060644u32.swap_bytes())],
                extra_data: b"x".to_vec(),
                extra_ops: s_file(0, 1, base_len()),
                extra_table: vec![(1, sum)],
                ..Spec::default()
            });
            assert!(
                err.contains("does not match") || err.contains("mode"),
                "{err}"
            );
        }

        #[test]
        fn a_file_streamed_in_pieces_is_assembled() {
            let content = b"hello, streamed world";
            let (sum, _) = file_object(content, 0o100644, "");
            let (a, b) = content.split_at(7);
            let base = base_len();

            let mut ops = vec![b'o'];
            ops.extend(varint(0));
            ops.extend(varint(0));
            ops.extend(varint(content.len() as u64));
            ops.push(b'w');
            ops.extend(varint(a.len() as u64));
            ops.extend(varint(base));
            ops.push(b'w');
            ops.extend(varint(b.len() as u64));
            ops.extend(varint(base + a.len() as u64));
            ops.push(b'c');

            let bundle = read_bundle(&build(&Spec {
                extra_data: content.to_vec(),
                extra_ops: ops,
                extra_table: vec![(1, sum)],
                ..Spec::default()
            }))
            .unwrap();
            let file = bundle
                .objects
                .iter()
                .find(|o| o.ty == ObjType::File)
                .unwrap();
            match &file.body {
                Body::File { content: got, .. } => assert_eq!(got, content),
                other => panic!("{other:?}"),
            }
        }

        fn stream_ops(size: u64, writes: &[(u64, u64)], close: bool) -> Vec<u8> {
            let mut ops = vec![b'o'];
            ops.extend(varint(0));
            ops.extend(varint(0));
            ops.extend(varint(size));
            for (len, off) in writes {
                ops.push(b'w');
                ops.extend(varint(*len));
                ops.extend(varint(*off));
            }
            if close {
                ops.push(b'c');
            }
            ops
        }

        #[test]
        fn a_streamed_file_closed_short_or_written_long_is_refused() {
            let (sum, _) = file_object(b"abcd", 0o100644, "");
            let base = base_len();
            let short = err_of(Spec {
                extra_data: b"abcd".to_vec(),
                extra_ops: stream_ops(4, &[(2, base)], true),
                extra_table: vec![(1, sum)],
                ..Spec::default()
            });
            assert!(short.contains("short of its declared size"), "{short}");

            let long = err_of(Spec {
                extra_data: b"abcd".to_vec(),
                extra_ops: stream_ops(2, &[(4, base)], true),
                extra_table: vec![(1, sum)],
                ..Spec::default()
            });
            assert!(long.contains("past its declared size"), "{long}");
        }

        #[test]
        fn a_streamed_file_with_the_wrong_content_is_refused() {
            let (sum, _) = file_object(b"abcd", 0o100644, "");
            let err = err_of(Spec {
                extra_data: b"WXYZ".to_vec(),
                extra_ops: stream_ops(4, &[(4, base_len())], true),
                extra_table: vec![(1, sum)],
                ..Spec::default()
            });
            assert!(err.contains("does not match its content"), "{err}");
        }

        #[test]
        fn stream_ops_out_of_order_are_refused() {
            let (sum, _) = file_object(b"ab", 0o100644, "");
            let base = base_len();
            let cases: Vec<(&str, Vec<u8>)> = vec![
                ("write with no open file", {
                    let mut o = vec![b'w'];
                    o.extend(varint(1));
                    o.extend(varint(base));
                    o
                }),
                ("close with no open file", vec![b'c']),
                (
                    "part ends with a file still open",
                    stream_ops(2, &[(2, base)], false),
                ),
                ("opened while another is open", {
                    let mut o = stream_ops(2, &[], false);
                    o.extend(stream_ops(2, &[], false));
                    o
                }),
                ("starts inside an open one", {
                    let mut o = stream_ops(2, &[], false);
                    o.extend(s_file(0, 2, base));
                    o
                }),
            ];
            for (needle, ops) in cases {
                let err = err_of(Spec {
                    extra_data: b"ab".to_vec(),
                    extra_ops: ops,
                    extra_table: vec![(1, sum), (1, sum)],
                    ..Spec::default()
                });
                assert!(err.contains(needle), "{needle}: {err}");
            }
        }

        #[test]
        fn ops_that_reach_for_a_parent_object_are_refused() {
            for op in *b"rB" {
                let err = err_of(Spec {
                    extra_ops: vec![op],
                    ..Spec::default()
                });
                assert!(err.contains("does not carry"), "{err}");
            }
            // `R` has nothing to unset and is accepted.
            read_bundle(&build(&Spec {
                extra_ops: vec![b'R'],
                ..Spec::default()
            }))
            .unwrap();
        }

        #[test]
        fn an_unknown_opcode_is_refused() {
            let err = err_of(Spec {
                extra_ops: vec![b'Z'],
                ..Spec::default()
            });
            assert!(err.contains("unknown delta opcode"), "{err}");
        }

        #[test]
        fn a_table_that_disagrees_with_the_ops_is_refused() {
            // More ops than table entries.
            let (sum, _) = file_object(b"x", 0o100644, "");
            let more_ops = err_of(Spec {
                extra_data: b"x".to_vec(),
                extra_ops: s_file(0, 1, base_len()),
                ..Spec::default()
            });
            assert!(
                more_ops.contains("more objects than the table"),
                "{more_ops}"
            );

            // Fewer ops than table entries.
            let fewer_ops = err_of(Spec {
                extra_table: vec![(1, sum)],
                ..Spec::default()
            });
            assert!(
                fewer_ops.contains("fewer objects than its table"),
                "{fewer_ops}"
            );

            // A table that is not a whole number of entries.
            let ragged = err_of(Spec {
                raw_table: Some(vec![1; 40]),
                ..Spec::default()
            });
            assert!(ragged.contains("whole number of entries"), "{ragged}");
        }

        #[test]
        fn out_of_range_indexes_and_offsets_are_refused() {
            let (sum, _) = file_object(b"x", 0o100644, "");
            let base = base_len();
            let bad_mode = err_of(Spec {
                extra_data: b"x".to_vec(),
                extra_ops: s_file(7, 1, base),
                extra_table: vec![(1, sum)],
                ..Spec::default()
            });
            assert!(bad_mode.contains("mode index"), "{bad_mode}");

            let bad_xattr = {
                let mut ops = vec![b'S'];
                ops.extend(varint(0));
                ops.extend(varint(9));
                ops.extend(varint(1));
                ops.extend(varint(base));
                err_of(Spec {
                    extra_data: b"x".to_vec(),
                    extra_ops: ops,
                    extra_table: vec![(1, sum)],
                    ..Spec::default()
                })
            };
            assert!(bad_xattr.contains("xattr index"), "{bad_xattr}");

            let bad_offset = err_of(Spec {
                extra_data: b"x".to_vec(),
                extra_ops: s_file(0, 1, base + 500),
                extra_table: vec![(1, sum)],
                ..Spec::default()
            });
            assert!(bad_offset.contains("outside its data"), "{bad_offset}");

            let overflow = err_of(Spec {
                extra_data: b"x".to_vec(),
                extra_ops: s_file(0, u64::MAX, 2),
                extra_table: vec![(1, sum)],
                ..Spec::default()
            });
            assert!(overflow.contains("overflows"), "{overflow}");
        }

        #[test]
        fn an_op_that_ends_mid_operand_is_refused() {
            let err = err_of(Spec {
                extra_ops: vec![b'S', 0x80],
                extra_table: vec![(3, Checksum([1; 32]))],
                ..Spec::default()
            });
            assert!(err.contains("mid-operand"), "{err}");
        }

        #[test]
        fn an_object_type_that_does_not_exist_is_refused() {
            let err = err_of(Spec {
                extra_table: vec![(9, Checksum([1; 32]))],
                extra_ops: s_file(0, 0, base_len()),
                ..Spec::default()
            });
            assert!(err.contains("unsupported object type"), "{err}");
        }

        #[test]
        fn a_file_object_cannot_be_given_the_metadata_treatment() {
            // The table says dirtree; the ops say file. A metadata slot
            // must be filled by an `S` that reads (length, offset).
            let err = err_of(Spec {
                extra_table: vec![(2, Checksum([1; 32]))],
                extra_ops: {
                    let mut o = vec![b'o'];
                    o.extend(varint(0));
                    o.extend(varint(0));
                    o.extend(varint(1));
                    o
                },
                ..Spec::default()
            });
            assert!(err.contains("only a file can be streamed"), "{err}");
        }
    }
}
