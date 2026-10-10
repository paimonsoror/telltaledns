//! MAC vendors (REQ: OBS-025, ADR-117) from the IEEE registry, compacted by
//! `presets/build-oui.py` into `presets/oui.bin` (format in that script). Read once, in place:
//! the vendor names are slices of the embedded table.

use std::sync::OnceLock;

static BLOB: &[u8] = include_bytes!("../../../../presets/oui.bin");
const MAGIC: &[u8; 8] = b"TTOUI1\0\0";
/// MA-M entry: u32 prefix (28 bits) + u16 vendor; MA-L: 3-byte prefix + u16 vendor.
const MAM: usize = 6;
const MAL: usize = 5;

struct Table {
    vendors: Vec<&'static str>,
    mam: &'static [u8],
    mal: &'static [u8],
}

fn u32_le(b: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

fn u16_le(b: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(..2)?.try_into().ok()?))
}

fn parse(blob: &'static [u8]) -> Option<Table> {
    if blob.get(..8)? != MAGIC {
        return None;
    }
    let vendor_count = usize::try_from(u32_le(blob.get(8..)?)?).ok()?;
    let mid_blocks = usize::try_from(u32_le(blob.get(12..)?)?).ok()?;
    let large_blocks = usize::try_from(u32_le(blob.get(16..)?)?).ok()?;
    let mut p = 20;
    let mut vendors = Vec::with_capacity(vendor_count);
    for _ in 0..vendor_count {
        let len = usize::from(*blob.get(p)?);
        let s = std::str::from_utf8(blob.get(p + 1..p + 1 + len)?).ok()?;
        vendors.push(s);
        p += 1 + len;
    }
    let mam = blob.get(p..p + mid_blocks * MAM)?;
    p += mid_blocks * MAM;
    let mal = blob.get(p..p + large_blocks * MAL)?;
    Some(Table { vendors, mam, mal })
}

fn table() -> Option<&'static Table> {
    static T: OnceLock<Option<Table>> = OnceLock::new();
    T.get_or_init(|| parse(BLOB)).as_ref()
}

/// Binary search over fixed-size entries whose key is `key(entry)`.
fn search(entries: &[u8], size: usize, want: u32, key: impl Fn(&[u8]) -> u32) -> Option<&[u8]> {
    let n = entries.len() / size;
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let e = entries.get(mid * size..(mid + 1) * size)?;
        match key(e).cmp(&want) {
            std::cmp::Ordering::Equal => return Some(e),
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    None
}

/// The vendor registered for `mac`'s prefix: the 28-bit (MA-M) block first, then the 24-bit
/// (MA-L) one. `None` for a locally administered address (a phone's private Wi-Fi address,
/// a VM) or an unregistered prefix.
pub(crate) fn lookup(mac: [u8; 6]) -> Option<&'static str> {
    if mac[0] & 0x02 != 0 {
        return None;
    }
    let t = table()?;
    let v28 = (u32::from(mac[0]) << 20)
        | (u32::from(mac[1]) << 12)
        | (u32::from(mac[2]) << 4)
        | (u32::from(mac[3]) >> 4);
    let v24 = (u32::from(mac[0]) << 16) | (u32::from(mac[1]) << 8) | u32::from(mac[2]);
    let idx = search(t.mam, MAM, v28, |e| u32_le(e).unwrap_or(u32::MAX))
        .and_then(|e| u16_le(e.get(4..)?))
        .or_else(|| {
            search(t.mal, MAL, v24, |e| {
                (u32::from(e[0]) << 16) | (u32::from(e[1]) << 8) | u32::from(e[2])
            })
            .and_then(|e| u16_le(e.get(3..)?))
        })?;
    t.vendors.get(usize::from(idx)).copied()
}

/// A MAC's registry prefix as shown in evidence (`D0:4D:2C`).
pub(crate) fn prefix_text(mac: [u8; 6]) -> String {
    format!("{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2])
}

/// `aa:bb:cc:dd:ee:ff` (or `-` separated) → bytes.
pub(crate) fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.trim().split([':', '-']);
    for b in &mut out {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// (vendors, MA-M prefixes, MA-L prefixes, bytes) of the embedded table.
pub(crate) fn stats() -> (usize, usize, usize, usize) {
    table().map_or((0, 0, 0, BLOB.len()), |t| {
        (
            t.vendors.len(),
            t.mam.len() / MAM,
            t.mal.len() / MAL,
            BLOB.len(),
        )
    })
}
