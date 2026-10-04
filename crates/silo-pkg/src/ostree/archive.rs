//! The `archive-z2` object encoding: how an object is stored in a
//! repository that clients fetch over plain HTTP.
//!
//! Metadata objects (`.dirtree`, `.dirmeta`, `.commit`) are stored as their
//! serialised GVariant bytes. A file object (`.filez`) is
//!
//! ```text
//! BE32(header length) BE32(0) header raw-deflate(content)
//! ```
//!
//! where the header is the `(tuuuusa(ayay))` of
//! [`FileMeta::archive_header`]. A symlink has a header and no stream.
//!
//! Decoding is the verification path for objects a client uploads: the
//! content is inflated under a bound, and the object's checksum is
//! recomputed from what came out.

use std::io::Write;

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;

use super::delta::{Body, Object};
use super::gvariant::Error;
use super::object::{file_checksum, Checksum, FileMeta, ObjType};
use crate::inflate_capped;

type Result<T> = std::result::Result<T, Error>;

/// The longest file header a decoder accepts.
///
/// A header is a few dozen bytes plus extended attributes; the bound
/// stops a crafted length field from asking for gigabytes of "header".
const MAX_HEADER_BYTES: usize = 16 * 1024 * 1024;

/// Encodes an object in its `archive-z2` form.
pub fn encode(object: &Object) -> Result<Vec<u8>> {
    match &object.body {
        Body::Metadata(bytes) => Ok(bytes.clone()),
        Body::File { meta, content } => encode_file(meta, content),
    }
}

pub fn encode_file(meta: &FileMeta, content: &[u8]) -> Result<Vec<u8>> {
    let header = meta.archive_header(content.len() as u64);
    let mut out = Vec::with_capacity(8 + header.len() + content.len() / 2);
    out.extend_from_slice(&(header.len() as u32).to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&header);
    if meta.is_regular() {
        let mut encoder = DeflateEncoder::new(out, Compression::default());
        encoder
            .write_all(content)
            .map_err(|e| Error(format!("could not compress file content: {e}")))?;
        out = encoder
            .finish()
            .map_err(|e| Error(format!("could not compress file content: {e}")))?;
    }
    Ok(out)
}

/// Decodes a `.filez` object, inflating at most `max_content` bytes.
pub fn decode_file(bytes: &[u8], max_content: u64) -> Result<(FileMeta, Vec<u8>)> {
    let Some(prefix) = bytes.get(..8) else {
        return Err(Error("file object is shorter than its framing".into()));
    };
    let header_len = u32::from_be_bytes(prefix[..4].try_into().expect("four bytes")) as usize;
    if header_len > MAX_HEADER_BYTES {
        return Err(Error("file object header is implausibly large".into()));
    }
    let Some(header) = bytes.get(8..8 + header_len) else {
        return Err(Error("file object header runs past its end".into()));
    };
    let (meta, size) = FileMeta::from_archive_header(header)?;
    let stream = &bytes[8 + header_len..];

    if meta.is_symlink() {
        if size != 0 || !stream.is_empty() {
            return Err(Error("a symlink object carries content".into()));
        }
        return Ok((meta, Vec::new()));
    }
    if size > max_content {
        return Err(Error(format!(
            "file object declares {size} bytes, past the {max_content} byte limit"
        )));
    }
    let content = inflate_capped(DeflateDecoder::new(stream), size, "file object")
        .map_err(|e| Error(e.to_string()))?;
    if content.len() as u64 != size {
        return Err(Error("file object is shorter than it declares".into()));
    }
    Ok((meta, content))
}

/// Decodes a stored object and returns its checksum, which is what the
/// object is named by only if it is intact.
pub fn checksum_of(ty: ObjType, bytes: &[u8], max_content: u64) -> Result<Checksum> {
    match ty {
        ObjType::File => {
            let (meta, content) = decode_file(bytes, max_content)?;
            Ok(file_checksum(&meta, &content))
        }
        _ => Ok(super::object::metadata_checksum(bytes)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ostree::delta::read_bundle;

    #[test]
    fn every_object_in_a_real_bundle_round_trips_through_archive_form() {
        let bundle = read_bundle(include_bytes!("../../tests/fixtures/hello.flatpak")).unwrap();
        for object in &bundle.objects {
            let bytes = encode(object).unwrap();
            let sum = checksum_of(object.ty, &bytes, 1 << 20).unwrap();
            assert_eq!(sum, object.checksum, "{:?}", object.ty);
        }
    }

    #[test]
    fn a_file_object_matches_the_bytes_ostree_wrote() {
        // 930fc258… from `flatpak build-export`: the same bytes, header
        // and deflate stream included.
        let ostree = include_bytes!("../../tests/fixtures/hello-script.filez");
        let (meta, content) = decode_file(ostree, 1 << 20).unwrap();
        assert_eq!(content, b"#!/bin/sh\necho hello\n");
        assert_eq!(meta.mode, 0o100755);
        let ours = encode_file(&meta, &content).unwrap();
        assert_eq!(&ours[..8 + 26], &ostree[..8 + 26], "framing and header");
        // The deflate stream may differ in level; it must decode alike.
        assert_eq!(decode_file(&ours, 1 << 20).unwrap().1, content);
    }

    #[test]
    fn a_symlink_has_a_header_and_no_stream() {
        let meta = FileMeta {
            uid: 0,
            gid: 0,
            mode: 0o120777,
            symlink_target: "../target".into(),
            xattrs: Vec::new(),
        };
        let bytes = encode_file(&meta, b"").unwrap();
        let (back, content) = decode_file(&bytes, 10).unwrap();
        assert_eq!(back, meta);
        assert!(content.is_empty());
    }

    #[test]
    fn a_decompression_bomb_is_refused() {
        let meta = FileMeta {
            uid: 0,
            gid: 0,
            mode: 0o100644,
            symlink_target: String::new(),
            xattrs: Vec::new(),
        };
        let bytes = encode_file(&meta, &vec![0u8; 1 << 20]).unwrap();
        assert!(bytes.len() < 4096, "zeroes compress hard");
        let err = decode_file(&bytes, 1024).unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
    }

    #[test]
    fn a_stream_shorter_than_declared_is_refused() {
        let meta = FileMeta {
            uid: 0,
            gid: 0,
            mode: 0o100644,
            symlink_target: String::new(),
            xattrs: Vec::new(),
        };
        let mut bytes = encode_file(&meta, b"hello world").unwrap();
        // Rewrite the declared size upward without touching the stream.
        let header = meta.archive_header(999);
        bytes.splice(8..8 + header.len(), header);
        assert!(decode_file(&bytes, 1 << 20).is_err());
    }

    #[test]
    fn malformed_framing_is_an_error_not_a_panic() {
        for bytes in [
            &b""[..],
            &b"\0\0\0\xff\0\0\0\0"[..],
            &b"\xff\xff\xff\xff\0\0\0\0"[..],
        ] {
            assert!(decode_file(bytes, 1 << 20).is_err());
        }
    }
}
