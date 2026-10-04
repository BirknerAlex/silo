//! OSTree object model: checksums, file headers, and the three metadata
//! object types (commit, directory tree, directory metadata).
//!
//! An object's name is the SHA-256 of its canonical byte form, so every
//! parser here is paired with the checksum that proves the bytes are what
//! they claim to be. Nothing imported from a client is trusted until its
//! checksum has been recomputed.
//!
//! - Metadata objects (commit, dirtree, dirmeta) are checksummed over the
//!   GVariant bytes themselves.
//! - A file object is checksummed over a *content stream*: the file's
//!   header (owner, mode, symlink target, xattrs) framed by its length,
//!   followed by its content. Two files with the same bytes but different
//!   modes are different objects.

use std::fmt;

use sha2::{Digest, Sha256};

use super::gvariant::{Error, Ty, Value, View};

type Result<T> = std::result::Result<T, Error>;

pub const CHECKSUM_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Checksum(pub [u8; CHECKSUM_LEN]);

impl Checksum {
    pub fn from_slice(bytes: &[u8]) -> Result<Checksum> {
        let arr: [u8; CHECKSUM_LEN] = bytes
            .try_into()
            .map_err(|_| Error(format!("checksum is {} bytes, not 32", bytes.len())))?;
        Ok(Checksum(arr))
    }

    pub fn from_hex(hex: &str) -> Result<Checksum> {
        let bytes = hex::decode(hex).map_err(|_| Error("checksum is not hexadecimal".into()))?;
        Checksum::from_slice(&bytes)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Checksum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Checksum({})", self.hex())
    }
}

impl fmt::Display for Checksum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObjType {
    File,
    DirTree,
    DirMeta,
    Commit,
}

impl ObjType {
    pub fn from_byte(b: u8) -> Result<ObjType> {
        match b {
            1 => Ok(ObjType::File),
            2 => Ok(ObjType::DirTree),
            3 => Ok(ObjType::DirMeta),
            4 => Ok(ObjType::Commit),
            other => Err(Error(format!("unsupported object type {other}"))),
        }
    }

    pub fn is_metadata(&self) -> bool {
        !matches!(self, ObjType::File)
    }

    /// The file extension an object has in an `archive` repository.
    pub fn archive_extension(&self) -> &'static str {
        match self {
            ObjType::File => "filez",
            ObjType::DirTree => "dirtree",
            ObjType::DirMeta => "dirmeta",
            ObjType::Commit => "commit",
        }
    }

    /// Parses an archive object filename extension.
    pub fn from_extension(ext: &str) -> Option<ObjType> {
        match ext {
            "filez" => Some(ObjType::File),
            "dirtree" => Some(ObjType::DirTree),
            "dirmeta" => Some(ObjType::DirMeta),
            "commit" => Some(ObjType::Commit),
            _ => None,
        }
    }

    /// Where the object lives relative to the repository root:
    /// `objects/ab/cdef….filez`.
    pub fn archive_path(&self, checksum: &Checksum) -> String {
        let hex = checksum.hex();
        format!(
            "objects/{}/{}.{}",
            &hex[..2],
            &hex[2..],
            self.archive_extension()
        )
    }
}

/// SHA-256 of a metadata object's serialised bytes.
pub fn metadata_checksum(bytes: &[u8]) -> Checksum {
    Checksum(Sha256::digest(bytes).into())
}

/// Ownership, mode and extended attributes of a file or symlink.
///
/// `uid`, `gid` and `mode` are held in host order; the wire stores them
/// big-endian inside an otherwise little-endian variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    /// Empty unless the object is a symlink.
    pub symlink_target: String,
    /// The serialised `a(ayay)`, kept opaque.
    pub xattrs: Vec<u8>,
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

impl FileMeta {
    pub fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }

    /// Rejects anything but a regular file or symlink. Devices, FIFOs and
    /// sockets have no place in an application tree, and an `archive`
    /// repository cannot represent them.
    pub fn validate(&self) -> Result<()> {
        if self.is_regular() && self.symlink_target.is_empty() || self.is_symlink() {
            Ok(())
        } else {
            Err(Error(format!("unsupported file mode {:o}", self.mode)))
        }
    }

    fn fields(&self) -> Vec<Value> {
        vec![
            Value::U32(self.uid.swap_bytes()),
            Value::U32(self.gid.swap_bytes()),
            Value::U32(self.mode.swap_bytes()),
            Value::U32(0),
            Value::str(&self.symlink_target),
            Value::Raw(xattrs_type(), self.xattrs.clone()),
        ]
    }

    /// The `(uuuusa(ayay))` header that precedes content in the stream a
    /// file object is checksummed over.
    pub fn header(&self) -> Vec<u8> {
        Value::Tuple(self.fields()).encode()
    }

    /// The `(tuuuusa(ayay))` header at the front of an `archive` file
    /// object, which adds the content size.
    pub fn archive_header(&self, size: u64) -> Vec<u8> {
        let mut fields = vec![Value::U64(size.swap_bytes())];
        fields.extend(self.fields());
        Value::Tuple(fields).encode()
    }

    /// Reads an `archive` file object header, returning it with the
    /// content size it declares.
    pub fn from_archive_header(bytes: &[u8]) -> Result<(FileMeta, u64)> {
        let view = View::new("(tuuuusa(ayay))", bytes)?;
        let size = view.child(0)?.as_u64()?.swap_bytes();
        Ok((FileMeta::from_view(&view, 1)?, size))
    }

    /// Reads fields `first..first+5` of a header tuple.
    pub fn from_view(view: &View<'_>, first: usize) -> Result<FileMeta> {
        let meta = FileMeta {
            uid: view.child(first)?.as_u32()?.swap_bytes(),
            gid: view.child(first + 1)?.as_u32()?.swap_bytes(),
            mode: view.child(first + 2)?.as_u32()?.swap_bytes(),
            symlink_target: view.child(first + 4)?.as_str()?.to_string(),
            xattrs: view.child(first + 5)?.bytes().to_vec(),
        };
        meta.validate()?;
        Ok(meta)
    }
}

fn xattrs_type() -> Ty {
    Ty::parse("a(ayay)").expect("static type string")
}

/// SHA-256 of a file's content stream.
pub fn file_checksum(meta: &FileMeta, content: &[u8]) -> Checksum {
    let header = meta.header();
    let mut hasher = Sha256::new();
    hasher.update((header.len() as u32).to_be_bytes());
    hasher.update([0u8; 4]);
    hasher.update(&header);
    hasher.update(content);
    Checksum(hasher.finalize().into())
}

/// A parsed commit object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub parent: Option<Checksum>,
    pub subject: String,
    pub body: String,
    /// Seconds since the epoch.
    pub timestamp: u64,
    pub root_tree: Checksum,
    pub root_meta: Checksum,
}

pub const COMMIT_TYPE: &str = "(a{sv}aya(say)sstayay)";

impl Commit {
    pub fn parse(bytes: &[u8]) -> Result<Commit> {
        let view = View::new(COMMIT_TYPE, bytes)?;
        let parent = view.child(1)?.as_byte_array()?;
        Ok(Commit {
            parent: if parent.is_empty() {
                None
            } else {
                Some(Checksum::from_slice(parent)?)
            },
            subject: view.child(3)?.as_str()?.to_string(),
            body: view.child(4)?.as_str()?.to_string(),
            timestamp: view.child(5)?.as_u64()?.swap_bytes(),
            root_tree: Checksum::from_slice(view.child(6)?.as_byte_array()?)?,
            root_meta: Checksum::from_slice(view.child(7)?.as_byte_array()?)?,
        })
    }

    /// The commit's `a{sv}` metadata.
    pub fn metadata<'a>(bytes: &'a [u8]) -> Result<View<'a>> {
        View::new(COMMIT_TYPE, bytes)?.child(0)
    }
}

/// A parsed directory tree object: the names it contains and the objects
/// they point at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirTree {
    pub files: Vec<(String, Checksum)>,
    /// `(name, dirtree, dirmeta)`.
    pub dirs: Vec<(String, Checksum, Checksum)>,
}

impl DirTree {
    pub fn parse(bytes: &[u8]) -> Result<DirTree> {
        let view = View::new("(a(say)a(sayay))", bytes)?;
        let mut files = Vec::new();
        for entry in view.child(0)?.iter()? {
            let entry = entry?;
            files.push((
                valid_name(entry.child(0)?.as_str()?)?,
                Checksum::from_slice(entry.child(1)?.as_byte_array()?)?,
            ));
        }
        let mut dirs = Vec::new();
        for entry in view.child(1)?.iter()? {
            let entry = entry?;
            dirs.push((
                valid_name(entry.child(0)?.as_str()?)?,
                Checksum::from_slice(entry.child(1)?.as_byte_array()?)?,
                Checksum::from_slice(entry.child(2)?.as_byte_array()?)?,
            ));
        }
        Ok(DirTree { files, dirs })
    }
}

/// An entry name must be a single path component, so nothing a tree
/// holds can name a path outside it once the tree is checked out.
fn valid_name(name: &str) -> Result<String> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(Error(format!("invalid directory entry name {name:?}")));
    }
    Ok(name.to_string())
}

/// Checks that a directory metadata object is well-formed: owner and mode
/// present, the mode a directory's, and every extended attribute a pair of
/// byte strings.
pub fn validate_dirmeta(bytes: &[u8]) -> Result<()> {
    let view = View::new("(uuua(ayay))", bytes)?;
    view.child(0)?.as_u32()?;
    view.child(1)?.as_u32()?;
    let mode = view.child(2)?.as_u32()?.swap_bytes();
    if mode & S_IFMT != S_IFDIR {
        return Err(Error(format!("directory metadata has mode {mode:o}")));
    }
    for xattr in view.child(3)?.iter()? {
        let xattr = xattr?;
        xattr.child(0)?.as_byte_array()?;
        xattr.child(1)?.as_byte_array()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_checksum_matches_what_ostree_computes() {
        // `#!/bin/sh\necho hello\n`, mode 0755, owned by root: object
        // 930fc258… in a repository built by `flatpak build-export`.
        let meta = FileMeta {
            uid: 0,
            gid: 0,
            mode: 0o100755,
            symlink_target: String::new(),
            xattrs: Vec::new(),
        };
        let sum = file_checksum(&meta, b"#!/bin/sh\necho hello\n");
        assert_eq!(
            sum.hex(),
            "930fc25874c26c343a792858523e747af11db9709ee14af708b8ff3fd81f9fc6"
        );
    }

    #[test]
    fn an_archive_header_round_trips() {
        let meta = FileMeta {
            uid: 1000,
            gid: 100,
            mode: 0o100644,
            symlink_target: String::new(),
            xattrs: Vec::new(),
        };
        let bytes = meta.archive_header(21);
        let (back, size) = FileMeta::from_archive_header(&bytes).unwrap();
        assert_eq!(back, meta);
        assert_eq!(size, 21);
    }

    #[test]
    fn a_device_node_is_refused() {
        let meta = FileMeta {
            uid: 0,
            gid: 0,
            mode: 0o060644,
            symlink_target: String::new(),
            xattrs: Vec::new(),
        };
        assert!(meta.validate().is_err());
    }

    #[test]
    fn entry_names_cannot_escape_their_directory() {
        for bad in ["", ".", "..", "a/b", "../x"] {
            assert!(valid_name(bad).is_err(), "{bad:?}");
        }
        assert!(valid_name("bin").is_ok());
    }

    #[test]
    fn checksums_parse_print_and_refuse_the_wrong_length() {
        let hex = "930fc25874c26c343a792858523e747af11db9709ee14af708b8ff3fd81f9fc6";
        let sum = Checksum::from_hex(hex).unwrap();
        assert_eq!(sum.hex(), hex);
        assert_eq!(sum.to_string(), hex);
        assert!(format!("{sum:?}").contains(hex));
        assert!(Checksum::from_hex("zz").is_err());
        assert!(Checksum::from_hex("abcd").is_err());
        assert!(Checksum::from_slice(&[0; 31]).is_err());
        assert!(Checksum::from_slice(&[0; 33]).is_err());
    }

    #[test]
    fn object_types_know_their_numbers_extensions_and_paths() {
        for (byte, ext, metadata) in [
            (1u8, "filez", false),
            (2, "dirtree", true),
            (3, "dirmeta", true),
            (4, "commit", true),
        ] {
            let ty = ObjType::from_byte(byte).unwrap();
            assert_eq!(ty.archive_extension(), ext);
            assert_eq!(ObjType::from_extension(ext), Some(ty));
            assert_eq!(ty.is_metadata(), metadata);
        }
        assert!(ObjType::from_byte(0).is_err());
        assert!(ObjType::from_byte(5).is_err());
        assert_eq!(ObjType::from_extension("commitmeta"), None);
        let sum = Checksum([0xab; 32]);
        assert_eq!(
            ObjType::DirTree.archive_path(&sum),
            format!("objects/ab/{}.dirtree", "ab".repeat(31))
        );
    }

    #[test]
    fn a_regular_file_cannot_carry_a_symlink_target() {
        let meta = FileMeta {
            uid: 0,
            gid: 0,
            mode: 0o100644,
            symlink_target: "x".into(),
            xattrs: Vec::new(),
        };
        assert!(meta.validate().is_err());
        let link = FileMeta {
            mode: 0o120777,
            ..meta.clone()
        };
        assert!(link.validate().is_ok());
        assert!(link.is_symlink() && !link.is_regular());
    }

    #[test]
    fn a_commit_dirtree_and_dirmeta_parse_and_malformed_ones_do_not() {
        let bundle =
            crate::ostree::delta::read_bundle(include_bytes!("../../tests/fixtures/hello.flatpak"))
                .unwrap();
        let commit = Commit::parse(&bundle.commit).unwrap();
        assert_eq!(commit.parent, None);
        assert_eq!(commit.subject, "Export org.example.Hello");
        assert!(commit.timestamp > 1_700_000_000);
        assert!(
            commit.body.contains("Built with: Flatpak"),
            "{}",
            commit.body
        );

        use crate::ostree::delta::Body;
        let tree = bundle
            .objects
            .iter()
            .find(|o| o.checksum == commit.root_tree)
            .unwrap();
        let Body::Metadata(bytes) = &tree.body else {
            panic!("a dirtree is metadata");
        };
        let parsed = DirTree::parse(bytes).unwrap();
        assert!(!parsed.dirs.is_empty() || !parsed.files.is_empty());
        let meta = bundle
            .objects
            .iter()
            .find(|o| o.checksum == commit.root_meta)
            .unwrap();
        let Body::Metadata(meta_bytes) = &meta.body else {
            panic!("a dirmeta is metadata");
        };
        validate_dirmeta(meta_bytes).unwrap();

        assert!(Commit::parse(b"garbage").is_err());
        assert!(DirTree::parse(b"garbage").is_err());
        assert!(validate_dirmeta(b"garbage").is_err());
        assert!(Commit::metadata(b"garbage").is_err());

        // A well-formed dirmeta whose mode is a regular file's is not a
        // directory's.
        let file_mode = Value::Tuple(vec![
            Value::U32(0),
            Value::U32(0),
            Value::U32(0o100644u32.swap_bytes()),
            Value::Array(Ty::parse("(ayay)").unwrap(), vec![]),
        ])
        .encode();
        let err = validate_dirmeta(&file_mode).unwrap_err().to_string();
        assert!(err.contains("mode"), "{err}");
        let with_xattr = Value::Tuple(vec![
            Value::U32(0),
            Value::U32(0),
            Value::U32(0o040755u32.swap_bytes()),
            Value::Array(
                Ty::parse("(ayay)").unwrap(),
                vec![Value::Tuple(vec![
                    Value::Bytes(b"user.x\0".to_vec()),
                    Value::Bytes(b"1".to_vec()),
                ])],
            ),
        ])
        .encode();
        validate_dirmeta(&with_xattr).unwrap();
    }

    #[test]
    fn a_commit_with_a_parent_reports_it() {
        let tree = metadata_checksum(b"t");
        let meta = metadata_checksum(b"m");
        let bytes = Value::Tuple(vec![
            Value::dict(vec![]),
            Value::Bytes(vec![7; 32]),
            Value::Array(Ty::parse("(say)").unwrap(), vec![]),
            Value::str("s"),
            Value::str("b"),
            Value::U64(5u64.swap_bytes()),
            Value::Bytes(tree.0.to_vec()),
            Value::Bytes(meta.0.to_vec()),
        ])
        .encode();
        let commit = Commit::parse(&bytes).unwrap();
        assert_eq!(commit.parent, Some(Checksum([7; 32])));
        assert_eq!(commit.timestamp, 5);
        assert_eq!(commit.body, "b");
        assert_eq!((commit.root_tree, commit.root_meta), (tree, meta));
    }
}
