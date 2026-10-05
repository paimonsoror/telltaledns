//! Reading the archives other DNS servers export (REQ: API-007): zip (Pi-hole v6 Teleporter)
//! and gzip-compressed tar (Pi-hole v5 Teleporter). Only the entries a caller asks for are
//! returned, each checked against its CRC-32 and a size limit, so a hostile or huge archive
//! can't exhaust memory.

use std::collections::BTreeMap;

/// Most bytes one entry may unpack to.
pub(crate) const ENTRY_LIMIT: usize = 512 << 20;

/// Entries keyed by their path inside the archive.
pub(crate) type Entries = BTreeMap<String, Vec<u8>>;

/// The entries of a zip or tar.gz archive for which `want(path)` is true.
pub(crate) fn read(data: &[u8], want: impl Fn(&str) -> bool) -> Result<Entries, String> {
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        zip(data, want)
    } else if data.starts_with(&[0x1f, 0x8b]) {
        tar(&gunzip(data)?, want)
    } else {
        Err("not a zip or tar.gz archive".into())
    }
}

fn u16_at(d: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes(d.get(at..at + 2)?.try_into().ok()?).into())
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, t) in (0u32..).zip(table.iter_mut()) {
        let mut c = i;
        for _ in 0..8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *t = c;
    }
    !data.iter().fold(!0u32, |c, &b| {
        table[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8)
    })
}

fn inflate(raw: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    miniz_oxide::inflate::decompress_to_vec_with_limit(raw, limit)
        .map_err(|e| format!("corrupt or too large compressed data ({:?})", e.status))
}

/// Zip via its central directory (no zip64, no encryption: Teleporter archives are small).
fn zip(d: &[u8], want: impl Fn(&str) -> bool) -> Result<Entries, String> {
    const EOCD: u32 = 0x0605_4b50;
    let bad = || "corrupt zip archive".to_string();
    // The end record is in the last 22 + 65535 (comment) bytes.
    let from = d.len().saturating_sub(22 + 0xffff);
    let eocd = (from..d.len().saturating_sub(21))
        .rev()
        .find(|&i| u32_at(d, i) == Some(EOCD))
        .ok_or_else(bad)?;
    let count = u16_at(d, eocd + 10).ok_or_else(bad)?;
    let mut at = u32_at(d, eocd + 16).ok_or_else(bad)? as usize;
    let mut out = Entries::new();
    for _ in 0..count {
        if u32_at(d, at) != Some(0x0201_4b50) {
            return Err(bad());
        }
        let flags = u16_at(d, at + 8).ok_or_else(bad)?;
        let method = u16_at(d, at + 10).ok_or_else(bad)?;
        let crc = u32_at(d, at + 16).ok_or_else(bad)?;
        let csize = u32_at(d, at + 20).ok_or_else(bad)?;
        let size = u32_at(d, at + 24).ok_or_else(bad)?;
        let name_len = u16_at(d, at + 28).ok_or_else(bad)?;
        let extra_len = u16_at(d, at + 30).ok_or_else(bad)?;
        let comment_len = u16_at(d, at + 32).ok_or_else(bad)?;
        let local = u32_at(d, at + 42).ok_or_else(bad)? as usize;
        let name = String::from_utf8_lossy(d.get(at + 46..at + 46 + name_len).ok_or_else(bad)?)
            .into_owned();
        at += 46 + name_len + extra_len + comment_len;
        if name.ends_with('/') || !want(&name) {
            continue;
        }
        if csize == u32::MAX || size == u32::MAX {
            return Err(format!("{name}: zip64 archives aren't supported"));
        }
        if flags & 1 == 1 {
            return Err(format!("{name}: encrypted zip entries aren't supported"));
        }
        if size as usize > ENTRY_LIMIT {
            return Err(format!("{name}: larger than {} MiB", ENTRY_LIMIT >> 20));
        }
        if u32_at(d, local) != Some(0x0403_4b50) {
            return Err(bad());
        }
        let start = local
            + 30
            + u16_at(d, local + 26).ok_or_else(bad)?
            + u16_at(d, local + 28).ok_or_else(bad)?;
        let raw = d.get(start..start + csize as usize).ok_or_else(bad)?;
        let data = match method {
            0 => raw.to_vec(),
            8 => inflate(raw, size as usize).map_err(|e| format!("{name}: {e}"))?,
            m => return Err(format!("{name}: unsupported compression method {m}")),
        };
        if data.len() != size as usize || crc32(&data) != crc {
            return Err(format!("{name}: checksum mismatch"));
        }
        out.insert(name, data);
    }
    Ok(out)
}

/// A gzip member (RFC 1952), checked against its CRC-32.
fn gunzip(d: &[u8]) -> Result<Vec<u8>, String> {
    let bad = || "corrupt gzip data".to_string();
    if d.len() < 18 || d[2] != 8 {
        return Err(bad());
    }
    let flg = d[3];
    let mut at = 10;
    if flg & 4 != 0 {
        at += 2 + u16_at(d, at).ok_or_else(bad)?;
    }
    for bit in [8, 16] {
        if flg & bit != 0 {
            at += 1 + d
                .get(at..)
                .ok_or_else(bad)?
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(bad)?;
        }
    }
    if flg & 2 != 0 {
        at += 2;
    }
    let body = d.get(at..d.len() - 8).ok_or_else(bad)?;
    let data = inflate(body, ENTRY_LIMIT)?;
    let crc = u32_at(d, d.len() - 8).ok_or_else(bad)?;
    if crc32(&data) != crc {
        return Err("gzip checksum mismatch".into());
    }
    Ok(data)
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// A tar stream (ustar, with GNU long names and pax `path`).
fn tar(d: &[u8], want: impl Fn(&str) -> bool) -> Result<Entries, String> {
    let bad = || "corrupt tar archive".to_string();
    let mut out = Entries::new();
    let mut at = 0;
    let mut long_name: Option<String> = None;
    while let Some(h) = d.get(at..at + 512) {
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let size_field = cstr(&h[124..136]);
        let size = usize::from_str_radix(size_field.trim(), 8).map_err(|_| bad())?;
        let body = d.get(at + 512..at + 512 + size).ok_or_else(bad)?;
        at += 512 + size.div_ceil(512) * 512;
        let mut name = cstr(&h[0..100]);
        if &h[257..262] == b"ustar" {
            let prefix = cstr(&h[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        match h[156] {
            b'L' => {
                long_name = Some(cstr(body));
                continue;
            }
            b'x' => {
                // Records are "<len> key=value\n".
                long_name = String::from_utf8_lossy(body)
                    .lines()
                    .find_map(|r| r.split_once(" path=").map(|(_, p)| p.to_owned()));
                continue;
            }
            b'0' | 0 => {}
            _ => {
                long_name = None;
                continue;
            }
        }
        let name = long_name.take().unwrap_or(name);
        let name = name.strip_prefix("./").unwrap_or(&name).to_owned();
        if want(&name) {
            out.insert(name, body.to_vec());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_007_crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    // Hand-built archives: a stored zip entry, and a deflated tar.gz.
    #[test]
    #[allow(clippy::cast_possible_truncation)] // tiny test sizes
    fn api_007_zip_and_tar_gz() {
        let mut z = Vec::new();
        // A stored zip with one entry "a/b.txt" = "hi\n", built by hand.
        let body = b"hi\n";
        let crc = crc32(body);
        let name = b"a/b.txt";
        z.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        z.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&3u32.to_le_bytes());
        z.extend_from_slice(&3u32.to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(name);
        z.extend_from_slice(body);
        let cd = z.len();
        z.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&3u32.to_le_bytes());
        z.extend_from_slice(&3u32.to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&[0; 12]);
        z.extend_from_slice(&0u32.to_le_bytes());
        z.extend_from_slice(name);
        let cd_len = z.len() - cd;
        z.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        z.extend_from_slice(&(cd_len as u32).to_le_bytes());
        z.extend_from_slice(&(cd as u32).to_le_bytes());
        z.extend_from_slice(&[0, 0]);
        let got = read(&z, |_| true).unwrap();
        assert_eq!(got.get("a/b.txt").map(Vec::as_slice), Some(&b"hi\n"[..]));
        // A flipped byte fails the checksum.
        let mut broken = z.clone();
        broken[30 + name.len()] ^= 1;
        assert!(read(&broken, |_| true).is_err());

        // tar.gz: one ustar entry, gzip-compressed (deflate via miniz_oxide).
        let mut t = vec![0u8; 512];
        t[..5].copy_from_slice(b"x.txt");
        t[124..135].copy_from_slice(b"00000000003");
        t[156] = b'0';
        t[257..262].copy_from_slice(b"ustar");
        t.extend_from_slice(b"yo\n");
        t.resize(1024 + 1024, 0);
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        gz.extend(miniz_oxide::deflate::compress_to_vec(&t, 6));
        gz.extend_from_slice(&crc32(&t).to_le_bytes());
        gz.extend_from_slice(&(t.len() as u32).to_le_bytes());
        let got = read(&gz, |n| n == "x.txt").unwrap();
        assert_eq!(got.get("x.txt").map(Vec::as_slice), Some(&b"yo\n"[..]));
        assert!(read(b"nope", |_| true).is_err());
    }
}
