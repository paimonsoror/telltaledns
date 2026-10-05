//! Packfiles: version 2, objects zlib-compressed, deltas against an earlier offset in the
//! pack (`ofs-delta`) or an object ID in it (`ref-delta`; thin packs are never requested).

use std::collections::HashMap;

use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};

/// An object's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }
}

/// A full (undeltified) object.
#[derive(Debug, Clone)]
pub struct Object {
    pub kind: Kind,
    pub data: Vec<u8>,
}

/// The object ID (SHA-1 hex) of `kind` + `data`.
pub fn oid(kind: Kind, data: &[u8]) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(format!("{} {}\0", kind.name(), data.len()).as_bytes());
    ctx.update(data);
    hex(ctx.finish().as_ref())
}

pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

/// Inflates one zlib stream at the start of `input`, at most `limit` bytes of output.
/// Returns the data and how many input bytes the stream took.
fn inflate_one(input: &[u8], size: usize, limit: usize) -> Result<(Vec<u8>, usize), String> {
    if size > limit {
        return Err(format!(
            "object of {size} bytes exceeds the {limit}-byte limit"
        ));
    }
    let mut state = InflateState::new_boxed(DataFormat::Zlib);
    let mut out = vec![0u8; size];
    let (mut read, mut written) = (0, 0);
    loop {
        let r = inflate(
            &mut state,
            &input[read..],
            &mut out[written..],
            MZFlush::Finish,
        );
        read += r.bytes_consumed;
        written += r.bytes_written;
        match r.status {
            Ok(MZStatus::StreamEnd) => break,
            Ok(_) if r.bytes_consumed == 0 && r.bytes_written == 0 => {
                return Err("truncated object in pack".into());
            }
            Ok(_) => {}
            Err(e) => return Err(format!("corrupt object in pack: {e:?}")),
        }
    }
    if written != size {
        return Err("object size mismatch in pack".into());
    }
    Ok((out, read))
}

/// Applies a delta to `base`.
fn apply_delta(base: &[u8], delta: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut p = 0;
    let mut varint = |d: &[u8]| -> Result<usize, String> {
        let (mut v, mut shift) = (0usize, 0);
        loop {
            let b = *d.get(p).ok_or("truncated delta")?;
            p += 1;
            v |= usize::from(b & 0x7f) << shift;
            shift += 7;
            if b & 0x80 == 0 || shift > 56 {
                return Ok(v);
            }
        }
    };
    let src = varint(delta)?;
    let dst = varint(delta)?;
    if src != base.len() {
        return Err("delta base size mismatch".into());
    }
    if dst > limit {
        return Err(format!(
            "object of {dst} bytes exceeds the {limit}-byte limit"
        ));
    }
    let mut out = Vec::with_capacity(dst);
    while p < delta.len() {
        let op = delta[p];
        p += 1;
        if op & 0x80 != 0 {
            let mut field = |bits: u8, shift_bits: [u32; 4], n: usize| -> Result<usize, String> {
                let mut v = 0usize;
                for (i, s) in shift_bits.iter().take(n).enumerate() {
                    if bits & (1 << i) != 0 {
                        v |= usize::from(*delta.get(p).ok_or("truncated delta")?) << s;
                        p += 1;
                    }
                }
                Ok(v)
            };
            let offset = field(op, [0, 8, 16, 24], 4)?;
            let mut size = field(op >> 4, [0, 8, 16, 0], 3)?;
            if size == 0 {
                size = 0x10000;
            }
            let chunk = base
                .get(offset..offset + size)
                .ok_or("delta copies outside its base")?;
            out.extend_from_slice(chunk);
        } else if op != 0 {
            let n = usize::from(op);
            out.extend_from_slice(delta.get(p..p + n).ok_or("truncated delta")?);
            p += n;
        } else {
            return Err("reserved delta opcode".into());
        }
    }
    if out.len() != dst {
        return Err("delta result size mismatch".into());
    }
    Ok(out)
}

/// Reads every object in a pack, resolving deltas. Each object is at most `limit` bytes.
pub fn read(pack: &[u8], limit: usize) -> Result<HashMap<String, Object>, String> {
    if pack.get(..4) != Some(b"PACK") {
        return Err("not a packfile".into());
    }
    let be32 = |i: usize| -> Result<u32, String> {
        let b: [u8; 4] = pack
            .get(i..i + 4)
            .ok_or("truncated pack")?
            .try_into()
            .map_err(|_| "pack")?;
        Ok(u32::from_be_bytes(b))
    };
    if be32(4)? != 2 {
        return Err("unsupported pack version".into());
    }
    let count = be32(8)? as usize;
    let mut p = 12;
    // Objects by their offset (for ofs-delta) and by ID (for ref-delta and the result).
    let mut at: HashMap<usize, (Kind, Vec<u8>)> = HashMap::new();
    let mut by_id: HashMap<String, Object> = HashMap::new();
    for _ in 0..count {
        let start = p;
        let mut b = *pack.get(p).ok_or("truncated pack")?;
        p += 1;
        let ty = (b >> 4) & 7;
        let mut size = usize::from(b & 0x0f);
        let mut shift = 4;
        while b & 0x80 != 0 {
            b = *pack.get(p).ok_or("truncated pack")?;
            p += 1;
            size |= usize::from(b & 0x7f) << shift;
            shift += 7;
            if shift > 60 {
                return Err("object size too large".into());
            }
        }
        let (kind, data) = match ty {
            1..=4 => {
                let (data, used) = inflate_one(&pack[p..], size, limit)?;
                p += used;
                let kind = match ty {
                    1 => Kind::Commit,
                    2 => Kind::Tree,
                    3 => Kind::Blob,
                    _ => Kind::Tag,
                };
                (kind, data)
            }
            6 => {
                // ofs-delta: base at (start - offset), offset in a big-endian base-128 varint.
                let mut c = *pack.get(p).ok_or("truncated pack")?;
                p += 1;
                let mut off = usize::from(c & 0x7f);
                while c & 0x80 != 0 {
                    c = *pack.get(p).ok_or("truncated pack")?;
                    p += 1;
                    off = ((off + 1) << 7) | usize::from(c & 0x7f);
                }
                let base_at = start.checked_sub(off).ok_or("bad delta offset")?;
                let (bk, base) = at.get(&base_at).ok_or("delta base missing")?;
                let (delta, used) = inflate_one(&pack[p..], size, limit)?;
                p += used;
                (*bk, apply_delta(base, &delta, limit)?)
            }
            7 => {
                let base_id = hex(pack.get(p..p + 20).ok_or("truncated pack")?);
                p += 20;
                let base = by_id
                    .get(&base_id)
                    .ok_or("ref-delta base not in the pack")?;
                let (delta, used) = inflate_one(&pack[p..], size, limit)?;
                p += used;
                (base.kind, apply_delta(&base.data, &delta, limit)?)
            }
            t => return Err(format!("unknown object type {t}")),
        };
        by_id.insert(
            oid(kind, &data),
            Object {
                kind,
                data: data.clone(),
            },
        );
        at.insert(start, (kind, data));
    }
    Ok(by_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_copy_and_insert() {
        let base = b"hello world";
        // src 11, dst 9: copy 5 from 0 ("hello"), insert " me!"
        let delta = [11u8, 9, 0x80 | 0x10, 5, 4, b' ', b'm', b'e', b'!'];
        assert_eq!(apply_delta(base, &delta, 100).unwrap(), b"hello me!");
        assert!(apply_delta(base, &delta, 3).is_err(), "over the limit");
    }

    #[test]
    fn object_ids_match_git() {
        // `echo -n hello | git hash-object --stdin`
        assert_eq!(
            oid(Kind::Blob, b"hello"),
            "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0"
        );
    }
}
