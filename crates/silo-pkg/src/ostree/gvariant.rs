//! A minimal GVariant codec: a bounds-checked reader and a writer.
//!
//! OSTree stores every piece of metadata — commits, directory trees,
//! static-delta superblocks, the repository `summary` — as GVariant, and a
//! Flatpak bundle is one too. Only the subset those formats use is
//! implemented: booleans, fixed-width integers, strings, variants, arrays
//! and tuples (a dictionary entry is a two-member tuple on the wire).
//! Maybe types and handles do not occur and are rejected.
//!
//! The reader works on untrusted bytes, so every offset it computes is
//! validated against the container it came from and every failure is an
//! [`Error`], never a panic. Values are little-endian; a big-endian
//! repository is refused one level up, where the byte order is declared.
//!
//! Layout rules, for the reader's benefit:
//!
//! - A fixed-size type occupies its natural size. A tuple of fixed-size
//!   members is fixed-size too, with members padded to their alignment and
//!   the whole rounded up to the tuple's alignment.
//! - A container of variable-size parts stores *framing offsets* — the end
//!   position of each variable-size part — in the smallest integer width
//!   that can address the container's total size. Arrays keep theirs in
//!   order after the last element; tuples keep theirs in reverse after the
//!   last member and omit the final member's, which ends where the offsets
//!   begin.
//! - A variant is its value, a NUL byte, then its type string.

use std::fmt;
use std::rc::Rc;

/// Deepest type nesting the reader accepts in a type string.
///
/// Variants carry their type as text taken from the input, so without a
/// bound a crafted type string could recurse the parser off the stack.
const MAX_TYPE_DEPTH: usize = 16;

/// Longest type string the reader accepts.
const MAX_TYPE_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error(msg.into()))
}

/// A GVariant type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ty {
    Bool,
    Byte,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F64,
    Str,
    ObjectPath,
    Signature,
    Variant,
    Array(Rc<Ty>),
    Tuple(Rc<[Ty]>),
    /// A dictionary entry `{kv}`. Serialised exactly like a two-member
    /// tuple, but spelled differently in a type string, and a reader
    /// checking `a{sv}` against `a(sv)` treats them as different types.
    Entry(Rc<[Ty]>),
}

impl Ty {
    fn members(&self) -> Option<&Rc<[Ty]>> {
        match self {
            Ty::Tuple(m) | Ty::Entry(m) => Some(m),
            _ => None,
        }
    }

    /// Parses a type string such as `(a{sv}tay)`.
    pub fn parse(s: &str) -> Result<Ty> {
        if s.len() > MAX_TYPE_LEN {
            return err("type string is too long");
        }
        let mut chars = s.chars().peekable();
        let ty = parse_one(&mut chars, 0)?;
        if chars.next().is_some() {
            return err(format!("trailing characters in type string {s:?}"));
        }
        Ok(ty)
    }

    /// The type as the string a variant carries.
    pub fn signature(&self) -> String {
        match self {
            Ty::Bool => "b".into(),
            Ty::Byte => "y".into(),
            Ty::I16 => "n".into(),
            Ty::U16 => "q".into(),
            Ty::I32 => "i".into(),
            Ty::U32 => "u".into(),
            Ty::I64 => "x".into(),
            Ty::U64 => "t".into(),
            Ty::F64 => "d".into(),
            Ty::Str => "s".into(),
            Ty::ObjectPath => "o".into(),
            Ty::Signature => "g".into(),
            Ty::Variant => "v".into(),
            Ty::Array(e) => format!("a{}", e.signature()),
            Ty::Tuple(members) => {
                let inner: String = members.iter().map(Ty::signature).collect();
                format!("({inner})")
            }
            Ty::Entry(members) => {
                let inner: String = members.iter().map(Ty::signature).collect();
                format!("{{{inner}}}")
            }
        }
    }

    fn alignment(&self) -> usize {
        match self {
            Ty::Bool | Ty::Byte | Ty::Str | Ty::ObjectPath | Ty::Signature => 1,
            Ty::I16 | Ty::U16 => 2,
            Ty::I32 | Ty::U32 => 4,
            Ty::I64 | Ty::U64 | Ty::F64 | Ty::Variant => 8,
            Ty::Array(e) => e.alignment(),
            Ty::Tuple(members) | Ty::Entry(members) => {
                members.iter().map(Ty::alignment).max().unwrap_or(1)
            }
        }
    }

    /// The type's size when every value of it has the same size.
    fn fixed_size(&self) -> Option<usize> {
        match self {
            Ty::Bool | Ty::Byte => Some(1),
            Ty::I16 | Ty::U16 => Some(2),
            Ty::I32 | Ty::U32 => Some(4),
            Ty::I64 | Ty::U64 | Ty::F64 => Some(8),
            Ty::Str | Ty::ObjectPath | Ty::Signature | Ty::Variant | Ty::Array(_) => None,
            Ty::Tuple(members) | Ty::Entry(members) => {
                let mut size = 0usize;
                for m in members.iter() {
                    size = align_up(size, m.alignment()) + m.fixed_size()?;
                }
                Some(align_up(size, self.alignment()).max(1))
            }
        }
    }
}

fn parse_one(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, depth: usize) -> Result<Ty> {
    if depth > MAX_TYPE_DEPTH {
        return err("type string nests too deeply");
    }
    let Some(c) = chars.next() else {
        return err("truncated type string");
    };
    Ok(match c {
        'b' => Ty::Bool,
        'y' => Ty::Byte,
        'n' => Ty::I16,
        'q' => Ty::U16,
        'i' => Ty::I32,
        'u' => Ty::U32,
        'x' => Ty::I64,
        't' => Ty::U64,
        'd' => Ty::F64,
        's' => Ty::Str,
        'o' => Ty::ObjectPath,
        'g' => Ty::Signature,
        'v' => Ty::Variant,
        'a' => Ty::Array(Rc::new(parse_one(chars, depth + 1)?)),
        '(' => {
            let mut members = Vec::new();
            loop {
                match chars.peek() {
                    Some(')') => {
                        chars.next();
                        break;
                    }
                    Some(_) => members.push(parse_one(chars, depth + 1)?),
                    None => return err("unterminated tuple type"),
                }
            }
            Ty::Tuple(members.into())
        }
        '{' => {
            let key = parse_one(chars, depth + 1)?;
            let value = parse_one(chars, depth + 1)?;
            if chars.next() != Some('}') {
                return err("malformed dictionary entry type");
            }
            Ty::Entry(vec![key, value].into())
        }
        other => return err(format!("unsupported type character {other:?}")),
    })
}

fn align_up(offset: usize, alignment: usize) -> usize {
    offset.div_ceil(alignment) * alignment
}

/// Width of a framing offset in a container of `len` bytes.
fn offset_size(len: usize) -> usize {
    if len <= 0xFF {
        1
    } else if len <= 0xFFFF {
        2
    } else if len <= 0xFFFF_FFFF {
        4
    } else {
        8
    }
}

fn read_uint(data: &[u8], at: usize, width: usize) -> Result<usize> {
    let bytes = data
        .get(
            at..at
                .checked_add(width)
                .ok_or_else(|| Error("offset overflow".into()))?,
        )
        .ok_or_else(|| Error("framing offset lies outside the container".into()))?;
    let mut buf = [0u8; 8];
    buf[..width].copy_from_slice(bytes);
    usize::try_from(u64::from_le_bytes(buf))
        .map_err(|_| Error("framing offset does not fit in memory".into()))
}

/// A typed window onto serialised bytes.
#[derive(Clone)]
pub struct View<'a> {
    ty: Ty,
    data: &'a [u8],
}

impl<'a> View<'a> {
    /// Interprets `data` as a value of the type spelled `ty`.
    pub fn new(ty: &str, data: &'a [u8]) -> Result<View<'a>> {
        View::with_type(Ty::parse(ty)?, data)
    }

    pub fn with_type(ty: Ty, data: &'a [u8]) -> Result<View<'a>> {
        if let Some(size) = ty.fixed_size() {
            if data.len() != size {
                return err(format!(
                    "a value of type {} is {size} bytes, found {}",
                    ty.signature(),
                    data.len()
                ));
            }
        }
        Ok(View { ty, data })
    }

    pub fn ty(&self) -> &Ty {
        &self.ty
    }

    /// The value's serialised bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }

    pub fn as_u8(&self) -> Result<u8> {
        match (&self.ty, self.data) {
            (Ty::Byte | Ty::Bool, [b]) => Ok(*b),
            _ => err("not a byte"),
        }
    }

    pub fn as_u32(&self) -> Result<u32> {
        match (&self.ty, self.data.try_into()) {
            (Ty::U32 | Ty::I32, Ok(b)) => Ok(u32::from_le_bytes(b)),
            _ => err("not a 32-bit integer"),
        }
    }

    pub fn as_u64(&self) -> Result<u64> {
        match (&self.ty, self.data.try_into()) {
            (Ty::U64 | Ty::I64, Ok(b)) => Ok(u64::from_le_bytes(b)),
            _ => err("not a 64-bit integer"),
        }
    }

    pub fn as_str(&self) -> Result<&'a str> {
        if !matches!(self.ty, Ty::Str | Ty::ObjectPath | Ty::Signature) {
            return err("not a string");
        }
        let Some((&0, text)) = self.data.split_last() else {
            return err("string is not NUL-terminated");
        };
        if text.contains(&0) {
            return err("string contains an interior NUL");
        }
        std::str::from_utf8(text).map_err(|_| Error("string is not valid UTF-8".into()))
    }

    /// The bytes of an `ay`.
    pub fn as_byte_array(&self) -> Result<&'a [u8]> {
        match &self.ty {
            Ty::Array(e) if **e == Ty::Byte => Ok(self.data),
            _ => err("not a byte array"),
        }
    }

    /// Number of members of a tuple.
    pub fn tuple_len(&self) -> Result<usize> {
        match self.ty.members() {
            Some(m) => Ok(m.len()),
            None => err("not a tuple"),
        }
    }

    /// The `index`th member of a tuple.
    pub fn child(&self, index: usize) -> Result<View<'a>> {
        let Some(members) = self.ty.members() else {
            return err("not a tuple");
        };
        let Some(member) = members.get(index) else {
            return err("tuple has no such member");
        };

        let last = members.len() - 1;
        let osz = offset_size(self.data.len());
        // Variable-size members excluding the last, which has no offset of
        // its own.
        let framed = members[..last]
            .iter()
            .filter(|m| m.fixed_size().is_none())
            .count();
        let frames_len = framed
            .checked_mul(osz)
            .filter(|n| *n <= self.data.len())
            .ok_or_else(|| Error("tuple framing offsets exceed the container".into()))?;
        let body_end = self.data.len() - frames_len;

        // Walk from the front so each member's start is derived from the
        // previous member's validated end.
        let mut start = 0usize;
        let mut seen_variable = 0usize;
        for (i, m) in members.iter().enumerate().take(index + 1) {
            start = align_up(start, m.alignment());
            let end = match m.fixed_size() {
                Some(size) => start
                    .checked_add(size)
                    .ok_or_else(|| Error("member size overflow".into()))?,
                None if i == last => body_end,
                None => {
                    let end =
                        read_uint(self.data, self.data.len() - osz * (seen_variable + 1), osz)?;
                    seen_variable += 1;
                    end
                }
            };
            if end < start || end > body_end {
                return err("tuple member lies outside its container");
            }
            if i == index {
                return View::with_type(member.clone(), &self.data[start..end]);
            }
            start = end;
        }
        unreachable!("the loop returns at `index`")
    }

    /// Number of elements of an array.
    pub fn len(&self) -> Result<usize> {
        let Ty::Array(elem) = &self.ty else {
            return err("not an array");
        };
        if self.data.is_empty() {
            return Ok(0);
        }
        match elem.fixed_size() {
            Some(size) => {
                if !self.data.len().is_multiple_of(size) {
                    return err("array length is not a multiple of its element size");
                }
                Ok(self.data.len() / size)
            }
            None => {
                let osz = offset_size(self.data.len());
                let frames_start =
                    read_uint(self.data, self.data.len() - osz.min(self.data.len()), osz)?;
                if frames_start > self.data.len()
                    || !(self.data.len() - frames_start).is_multiple_of(osz)
                {
                    return err("array framing offsets are malformed");
                }
                Ok((self.data.len() - frames_start) / osz)
            }
        }
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// The `index`th element of an array.
    pub fn at(&self, index: usize) -> Result<View<'a>> {
        let Ty::Array(elem) = &self.ty else {
            return err("not an array");
        };
        let count = self.len()?;
        if index >= count {
            return err("array index out of range");
        }
        match elem.fixed_size() {
            Some(size) => View::with_type(
                (**elem).clone(),
                &self.data[index * size..(index + 1) * size],
            ),
            None => {
                let osz = offset_size(self.data.len());
                let frames_start = self.data.len() - count * osz;
                let end = read_uint(self.data, frames_start + index * osz, osz)?;
                let prev_end = if index == 0 {
                    0
                } else {
                    read_uint(self.data, frames_start + (index - 1) * osz, osz)?
                };
                let start = align_up(prev_end, elem.alignment());
                if end < start || end > frames_start {
                    return err("array element lies outside its container");
                }
                View::with_type((**elem).clone(), &self.data[start..end])
            }
        }
    }

    /// Iterates an array's elements.
    pub fn iter(&self) -> Result<impl Iterator<Item = Result<View<'a>>> + '_> {
        let n = self.len()?;
        Ok((0..n).map(move |i| self.at(i)))
    }

    /// Unwraps a variant.
    pub fn variant(&self) -> Result<View<'a>> {
        if self.ty != Ty::Variant {
            return err("not a variant");
        }
        let Some(split) = self.data.iter().rposition(|b| *b == 0) else {
            return err("variant has no type string");
        };
        let ty = std::str::from_utf8(&self.data[split + 1..])
            .map_err(|_| Error("variant type is not UTF-8".into()))?;
        View::new(ty, &self.data[..split])
    }

    /// Looks a key up in an `a{sv}` and unwraps its value.
    pub fn dict_get(&self, key: &str) -> Result<Option<View<'a>>> {
        for entry in self.iter()? {
            let entry = entry?;
            if entry.child(0)?.as_str()? == key {
                return Ok(Some(entry.child(1)?.variant()?));
            }
        }
        Ok(None)
    }
}

/// A value to serialise.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    Byte(u8),
    U32(u32),
    U64(u64),
    Str(String),
    /// An `ay`.
    Bytes(Vec<u8>),
    /// A variant wrapping another value.
    Variant(Box<Value>),
    /// An array; the element type is explicit so an empty array is typed.
    Array(Ty, Vec<Value>),
    Tuple(Vec<Value>),
    /// Already-serialised bytes of the given type, passed through as-is.
    /// Carries extended attributes from one object to another without
    /// decoding them.
    Raw(Ty, Vec<u8>),
}

impl Value {
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }

    pub fn variant(v: Value) -> Value {
        Value::Variant(Box::new(v))
    }

    /// A dictionary entry `{sv}`.
    pub fn entry(key: impl Into<String>, value: Value) -> Value {
        Value::Tuple(vec![Value::str(key), Value::variant(value)])
    }

    /// An `a{sv}` from entries.
    pub fn dict(entries: Vec<Value>) -> Value {
        Value::Array(Ty::Entry(vec![Ty::Str, Ty::Variant].into()), entries)
    }

    pub fn ty(&self) -> Ty {
        match self {
            Value::Bool(_) => Ty::Bool,
            Value::Byte(_) => Ty::Byte,
            Value::U32(_) => Ty::U32,
            Value::U64(_) => Ty::U64,
            Value::Str(_) => Ty::Str,
            Value::Bytes(_) => Ty::Array(Rc::new(Ty::Byte)),
            Value::Variant(_) => Ty::Variant,
            Value::Array(e, _) => Ty::Array(Rc::new(e.clone())),
            Value::Tuple(m) => Ty::Tuple(m.iter().map(Value::ty).collect::<Vec<_>>().into()),
            Value::Raw(ty, _) => ty.clone(),
        }
    }

    /// Serialises the value.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Value::Bool(v) => vec![u8::from(*v)],
            Value::Byte(v) => vec![*v],
            Value::U32(v) => v.to_le_bytes().to_vec(),
            Value::U64(v) => v.to_le_bytes().to_vec(),
            Value::Str(s) => {
                let mut out = s.as_bytes().to_vec();
                out.push(0);
                out
            }
            Value::Bytes(b) => b.clone(),
            Value::Raw(_, b) => b.clone(),
            Value::Variant(inner) => {
                let mut out = inner.encode();
                out.push(0);
                out.extend_from_slice(inner.ty().signature().as_bytes());
                out
            }
            Value::Array(elem, items) => {
                if elem.fixed_size().is_some() {
                    return items.iter().flat_map(Value::encode).collect();
                }
                let mut out = Vec::new();
                let mut ends = Vec::with_capacity(items.len());
                for item in items {
                    pad(&mut out, elem.alignment());
                    out.extend_from_slice(&item.encode());
                    ends.push(out.len());
                }
                if items.is_empty() {
                    return out;
                }
                append_frames(out, &ends)
            }
            Value::Tuple(members) => {
                let ty = self.ty();
                let last = members.len().saturating_sub(1);
                let mut out = Vec::new();
                let mut ends = Vec::new();
                for (i, m) in members.iter().enumerate() {
                    let mty = m.ty();
                    pad(&mut out, mty.alignment());
                    out.extend_from_slice(&m.encode());
                    if mty.fixed_size().is_none() && i != last {
                        ends.push(out.len());
                    }
                }
                if ty.fixed_size().is_some() {
                    pad(&mut out, ty.alignment());
                    if out.is_empty() {
                        out.push(0);
                    }
                    return out;
                }
                // Tuples keep their offsets in reverse.
                ends.reverse();
                append_frames(out, &ends)
            }
        }
    }
}

fn pad(out: &mut Vec<u8>, alignment: usize) {
    out.resize(align_up(out.len(), alignment), 0);
}

/// Appends framing offsets to `body`, picking the narrowest width that
/// addresses the finished container.
fn append_frames(mut body: Vec<u8>, ends: &[usize]) -> Vec<u8> {
    if ends.is_empty() {
        return body;
    }
    let osz = [1usize, 2, 4, 8]
        .into_iter()
        .find(|w| {
            let total = body.len() + ends.len() * w;
            *w == 8 || (total as u64) < (1u64 << (8 * *w))
        })
        .unwrap_or(8);
    for end in ends {
        body.extend_from_slice(&(*end as u64).to_le_bytes()[..osz]);
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_integers_and_variants_round_trip() {
        let v = Value::Tuple(vec![Value::U32(7), Value::str("hello"), Value::U64(9)]);
        let bytes = v.encode();
        let view = View::new("(usx)", &bytes);
        // `x` is signed but shares `t`'s encoding; the point is that the
        // reader agrees with the writer on layout and padding.
        let view = view.unwrap();
        assert_eq!(view.child(0).unwrap().as_u32().unwrap(), 7);
        assert_eq!(view.child(1).unwrap().as_str().unwrap(), "hello");
        assert_eq!(view.child(2).unwrap().as_u64().unwrap(), 9);
    }

    #[test]
    fn a_dictionary_is_looked_up_by_key() {
        let dict = Value::dict(vec![
            Value::entry("name", Value::str("org.example.Hello")),
            Value::entry("size", Value::U64(42)),
            Value::entry("flag", Value::Byte(1)),
        ]);
        let bytes = dict.encode();
        let view = View::new("a{sv}", &bytes).unwrap();
        assert_eq!(
            view.dict_get("name").unwrap().unwrap().as_str().unwrap(),
            "org.example.Hello"
        );
        assert_eq!(
            view.dict_get("size").unwrap().unwrap().as_u64().unwrap(),
            42
        );
        assert!(view.dict_get("absent").unwrap().is_none());
    }

    #[test]
    fn a_container_wider_than_255_bytes_uses_wider_offsets() {
        let entries: Vec<Value> = (0..40)
            .map(|i| Value::entry(format!("key-{i}"), Value::str("x".repeat(20))))
            .collect();
        let bytes = Value::dict(entries).encode();
        assert!(bytes.len() > 0xFF);
        let view = View::new("a{sv}", &bytes).unwrap();
        assert_eq!(view.len().unwrap(), 40);
        assert_eq!(
            view.dict_get("key-39").unwrap().unwrap().as_str().unwrap(),
            "x".repeat(20)
        );
    }

    #[test]
    fn a_tuple_with_a_trailing_fixed_member_reads_back() {
        // Variable member first, fixed member last: the offset exists for
        // the first and the last member ends at the offsets' start minus
        // nothing, so this is the shape that exercises both paths.
        let v = Value::Tuple(vec![Value::str("abc"), Value::U64(5)]);
        let bytes = v.encode();
        let view = View::new("(st)", &bytes).unwrap();
        assert_eq!(view.child(0).unwrap().as_str().unwrap(), "abc");
        assert_eq!(view.child(1).unwrap().as_u64().unwrap(), 5);
    }

    #[test]
    fn truncated_and_hostile_input_is_an_error_not_a_panic() {
        let good = Value::dict(vec![Value::entry("k", Value::str("value"))]).encode();
        for cut in 0..good.len() {
            if let Ok(view) = View::new("a{sv}", &good[..cut]) {
                let _ = view.dict_get("k");
            }
        }
        // An offset pointing far past the container.
        let mut bad = good.clone();
        let last = bad.len() - 1;
        bad[last] = 0xFF;
        if let Ok(view) = View::new("a{sv}", &bad) {
            let _ = view.dict_get("k");
        }
    }

    #[test]
    fn type_strings_are_bounded() {
        assert!(Ty::parse(&"a".repeat(MAX_TYPE_DEPTH + 2)).is_err());
        assert!(Ty::parse(&"(".repeat(MAX_TYPE_LEN + 1)).is_err());
        assert!(Ty::parse("(a{sv}tay)").is_ok());
        assert!(Ty::parse("m").is_err());
    }

    #[test]
    fn a_real_bundle_parses() {
        let bytes = include_bytes!("../../tests/fixtures/hello.flatpak");
        let view = View::new(
            "(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))",
            bytes,
        )
        .unwrap();
        let meta = view.child(0).unwrap();
        assert_eq!(
            meta.dict_get("ref").unwrap().unwrap().as_str().unwrap(),
            "app/org.example.Hello/x86_64/stable"
        );
        let to = view.child(3).unwrap();
        assert_eq!(to.as_byte_array().unwrap().len(), 32);
    }

    #[test]
    fn type_strings_round_trip_and_malformed_ones_are_refused() {
        for sig in [
            "b",
            "y",
            "n",
            "q",
            "i",
            "u",
            "x",
            "t",
            "d",
            "s",
            "o",
            "g",
            "v",
            "ay",
            "a{sv}",
            "(a{sv}tayay)",
            "a(say)",
            "()",
        ] {
            assert_eq!(Ty::parse(sig).unwrap().signature(), sig);
        }
        for bad in [
            "", "(", "(s", "a", "{s}", "{sv", "{svv}", "sy", ")", "{sv}x",
        ] {
            assert!(Ty::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_fixed_size_type_must_be_exactly_that_size() {
        assert!(View::new("u", &[0, 0, 0]).is_err());
        assert!(View::new("u", &[0, 0, 0, 0]).is_ok());
        assert!(View::new("(yu)", &[0; 7]).is_err());
        assert!(View::new("(yu)", &[0; 8]).is_ok());
        assert!(View::new("()", &[0]).is_ok());
    }

    #[test]
    fn accessors_refuse_the_wrong_type() {
        let int = Value::U32(5).encode();
        let int = View::new("u", &int).unwrap();
        assert!(int.as_str().is_err());
        assert!(int.as_u64().is_err());
        assert!(int.as_u8().is_err());
        assert!(int.as_byte_array().is_err());
        assert!(int.tuple_len().is_err());
        assert!(int.child(0).is_err());
        assert!(int.len().is_err());
        assert!(int.at(0).is_err());
        assert!(int.variant().is_err());
        assert!(int.iter().is_err());

        let long = Value::U64(5).encode();
        assert!(View::new("t", &long).unwrap().as_u32().is_err());
        let byte = View::new("y", &[7]).unwrap();
        assert_eq!(byte.as_u8().unwrap(), 7);
        assert_eq!(View::new("b", &[1]).unwrap().as_u8().unwrap(), 1);
    }

    #[test]
    fn strings_must_be_terminated_unbroken_and_utf8() {
        assert!(View::new("s", b"no terminator").unwrap().as_str().is_err());
        assert!(View::new("s", b"a\0b\0").unwrap().as_str().is_err());
        assert!(View::new("s", b"\xff\xfe\0").unwrap().as_str().is_err());
        assert!(View::new("s", b"").unwrap().as_str().is_err());
        assert_eq!(View::new("s", b"fine\0").unwrap().as_str().unwrap(), "fine");
        assert_eq!(View::new("o", b"/a\0").unwrap().as_str().unwrap(), "/a");
    }

    #[test]
    fn tuple_and_array_indexing_is_bounds_checked() {
        let tuple = Value::Tuple(vec![Value::str("a"), Value::U32(1)]).encode();
        let tuple = View::new("(su)", &tuple).unwrap();
        assert_eq!(tuple.tuple_len().unwrap(), 2);
        assert!(tuple.child(2).is_err());

        let array = Value::Array(Ty::U32, vec![Value::U32(1), Value::U32(2)]).encode();
        let array = View::new("au", &array).unwrap();
        assert_eq!(array.len().unwrap(), 2);
        assert!(!array.is_empty().unwrap());
        assert_eq!(array.at(1).unwrap().as_u32().unwrap(), 2);
        assert!(array.at(2).is_err());
        let all: Vec<u32> = array
            .iter()
            .unwrap()
            .map(|v| v.unwrap().as_u32().unwrap())
            .collect();
        assert_eq!(all, vec![1, 2]);

        // A length that is not a whole number of elements.
        assert!(View::new("au", &[0; 5]).unwrap().len().is_err());
        assert!(View::new("au", &[]).unwrap().is_empty().unwrap());
    }

    #[test]
    fn a_variant_needs_a_type_string_that_parses() {
        assert!(View::new("v", b"").unwrap().variant().is_err());
        assert!(View::new("v", b"abc").unwrap().variant().is_err());
        // Value, NUL, then a type that is not UTF-8.
        assert!(View::new("v", b"\0\0\xff").unwrap().variant().is_err());
        // Value, NUL, then a type the reader does not know.
        assert!(View::new("v", b"x\0m").unwrap().variant().is_err());
        let ok = Value::variant(Value::U32(9)).encode();
        assert_eq!(
            View::new("v", &ok)
                .unwrap()
                .variant()
                .unwrap()
                .as_u32()
                .unwrap(),
            9
        );
    }

    #[test]
    fn nested_variants_booleans_and_fixed_tuples_encode_and_read_back() {
        let nested = Value::variant(Value::variant(Value::str("deep"))).encode();
        let outer = View::new("v", &nested).unwrap();
        let inner = outer.variant().unwrap();
        assert_eq!(inner.variant().unwrap().as_str().unwrap(), "deep");

        assert_eq!(Value::Bool(true).encode(), vec![1]);
        assert_eq!(Value::Bool(false).ty(), Ty::Bool);
        assert_eq!(Value::Byte(3).encode(), vec![3]);

        // A tuple of fixed-size members pads to its alignment.
        let fixed = Value::Tuple(vec![Value::Byte(1), Value::U64(2)]).encode();
        assert_eq!(fixed.len(), 16);
        let view = View::new("(yt)", &fixed).unwrap();
        assert_eq!(view.child(0).unwrap().as_u8().unwrap(), 1);
        assert_eq!(view.child(1).unwrap().as_u64().unwrap(), 2);
        assert_eq!(Value::Tuple(vec![]).encode(), vec![0]);

        // Raw bytes pass through under the type they are given.
        let raw = Value::Raw(Ty::U32, vec![1, 0, 0, 0]);
        assert_eq!(raw.ty(), Ty::U32);
        assert_eq!(raw.encode(), vec![1, 0, 0, 0]);
    }

    #[test]
    fn an_array_of_arrays_with_wide_framing_round_trips() {
        let rows: Vec<Value> = (0..300)
            .map(|i| Value::Array(Ty::Byte, vec![Value::Byte((i % 251) as u8); 3]))
            .collect();
        let bytes = Value::Array(Ty::parse("ay").unwrap(), rows).encode();
        assert!(
            bytes.len() > 0xFF && bytes.len() <= 0xFFFF,
            "two-byte offsets"
        );
        let view = View::new("aay", &bytes).unwrap();
        assert_eq!(view.len().unwrap(), 300);
        assert_eq!(
            view.at(299).unwrap().as_byte_array().unwrap(),
            &[48, 48, 48]
        );
    }

    #[test]
    fn corrupt_framing_offsets_are_refused() {
        // A tuple whose offset points past the end.
        let mut tuple = Value::Tuple(vec![Value::str("abc"), Value::str("de")]).encode();
        let last = tuple.len() - 1;
        tuple[last] = 0xF0;
        let view = View::new("(ss)", &tuple).unwrap();
        assert!(view.child(0).is_err());

        // An array whose final offset is not a multiple of the element count.
        let mut array = Value::Array(Ty::Str, vec![Value::str("a"), Value::str("b")]).encode();
        let last = array.len() - 1;
        array[last] = 0xF0;
        let view = View::new("as", &array).unwrap();
        assert!(view.len().is_err() || view.at(0).is_err());
    }
}
