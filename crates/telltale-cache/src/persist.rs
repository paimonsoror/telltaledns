//! Cache persistence (REQ: DNS-009; T6.2): an optional dump on shutdown and load on start, so
//! a restart doesn't begin with a cold cache.
//!
//! Format (little-endian): `TTC1`, a 64-bit fingerprint, the dump time (Unix seconds, so
//! downtime ages every entry), then per entry: qtype u16, qclass
//! u16, flags u8, view u16, age u32 (seconds), ttl u32, hits u32, `question_end` u16, name
//! (u16 length + bytes), wire (u32 length + bytes), and TTL offsets (u16 count + u16 each).
//!
//! - **Fingerprint:** a "view" is a position in the routing configuration, so the dump
//!   carries a fingerprint of it. A dump taken under different upstreams or routes is
//!   ignored rather than serving one group's answer to another.
//! - **Re-keyed on load:** keys hash the name with a per-process seed, so they're recomputed.
//! - **What's kept:** an entry is loaded only while it can still be served (fresh, or within
//!   the serve-stale window).

use std::io::{self, Write};
use std::time::{Duration, Instant};

use crate::entry::Entry;
use crate::{Cache, CacheKey};

const MAGIC: &[u8; 4] = b"TTC1";

impl Cache {
    /// Writes every entry to `out`; returns how many.
    pub fn dump(&self, now: Instant, fingerprint: u64, out: &mut impl Write) -> io::Result<usize> {
        out.write_all(MAGIC)?;
        out.write_all(&fingerprint.to_le_bytes())?;
        out.write_all(&unix_now().to_le_bytes())?;
        let mut n = 0;
        let mut err = None;
        for s in &self.shards {
            s.0.lock().fifo.retain(|k, e| {
                if err.is_none()
                    && let Err(x) = write_entry(out, k, e, now)
                {
                    err = Some(x);
                }
                n += 1;
                true
            });
        }
        match err {
            Some(e) => Err(e),
            None => Ok(n),
        }
    }

    /// Loads a dump written by [`Cache::dump`] under the same `fingerprint`. `name_hash` is
    /// this process's hash of a wire-format name. Entries that can no longer be served are
    /// skipped. Returns how many were loaded.
    pub fn load(
        &self,
        data: &[u8],
        now: Instant,
        fingerprint: u64,
        name_hash: impl Fn(&[u8]) -> Option<u64>,
    ) -> Result<usize, String> {
        let mut r = Reader(data);
        if r.take(4)? != MAGIC {
            return Err("not a cache dump".into());
        }
        if r.u64()? != fingerprint {
            return Err("taken under different upstreams or routes; not loading it".into());
        }
        // Time spent down ages every entry.
        let down = u32::try_from(unix_now().saturating_sub(r.u64()?)).unwrap_or(u32::MAX);
        let stale = if self.policy.serve_stale {
            self.policy.stale_max_age
        } else {
            0
        };
        let mut loaded = 0;
        while !r.0.is_empty() {
            let (qtype, qclass, flags, view) = (r.u16()?, r.u16()?, r.u8()?, r.u16()?);
            let (age, ttl, hits, question_end) = (r.u32()?, r.u32()?, r.u32()?, r.u16()?);
            let age = age.saturating_add(down);
            let name: Box<[u8]> = r.bytes16()?.into();
            let wire: Box<[u8]> = r.bytes32()?.into();
            let count = usize::from(r.u16()?);
            let mut offsets = Vec::with_capacity(count);
            for _ in 0..count {
                offsets.push(r.u16()?);
            }
            if age >= ttl.saturating_add(stale) || usize::from(question_end) > wire.len() {
                continue;
            }
            if offsets.iter().any(|&o| usize::from(o) + 4 > wire.len()) {
                return Err("corrupt dump (TTL offset outside the answer)".into());
            }
            let Some(h) = name_hash(&name) else { continue };
            let Some(inserted) = now.checked_sub(Duration::from_secs(u64::from(age))) else {
                continue;
            };
            let key = CacheKey::from_parts(h, qtype, qclass, flags, view);
            let e = Entry {
                name,
                wire,
                ttl_offsets: offsets.into(),
                question_end,
                inserted,
                ttl,
                hits,
                prefetch_signaled: false,
            };
            let w = e.weight();
            self.shard(&key).lock().fifo.insert(key, e, w);
            loaded += 1;
        }
        Ok(loaded)
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn write_entry(out: &mut impl Write, k: &CacheKey, e: &Entry, now: Instant) -> io::Result<()> {
    let too_big = || io::Error::other("entry too large");
    out.write_all(&k.qtype.to_le_bytes())?;
    out.write_all(&k.qclass.to_le_bytes())?;
    out.write_all(&[k.flags])?;
    out.write_all(&k.view.to_le_bytes())?;
    out.write_all(&e.elapsed_secs(now).to_le_bytes())?;
    out.write_all(&e.ttl.to_le_bytes())?;
    out.write_all(&e.hits.to_le_bytes())?;
    out.write_all(&e.question_end.to_le_bytes())?;
    out.write_all(
        &u16::try_from(e.name.len())
            .map_err(|_| too_big())?
            .to_le_bytes(),
    )?;
    out.write_all(&e.name)?;
    out.write_all(
        &u32::try_from(e.wire.len())
            .map_err(|_| too_big())?
            .to_le_bytes(),
    )?;
    out.write_all(&e.wire)?;
    out.write_all(
        &u16::try_from(e.ttl_offsets.len())
            .map_err(|_| too_big())?
            .to_le_bytes(),
    )?;
    for o in &e.ttl_offsets {
        out.write_all(&o.to_le_bytes())?;
    }
    Ok(())
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let b = self.0.get(..n).ok_or("truncated cache dump")?;
        self.0 = &self.0[n..];
        Ok(b)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| "dump")?,
        ))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| "dump")?,
        ))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| "dump")?,
        ))
    }
    fn bytes16(&mut self) -> Result<&'a [u8], String> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
    fn bytes32(&mut self) -> Result<&'a [u8], String> {
        let n = usize::try_from(self.u32()?).map_err(|_| "dump")?;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use telltale_proto::{NameBuf, parse_query};

    use crate::{Cache, CacheKey, CachePolicy, Client};

    fn query(name: &str) -> Vec<u8> {
        let n = NameBuf::from_presentation(name).unwrap();
        let mut b = vec![0u8; 512];
        let len = telltale_proto::build_query(&mut b, 7, &n, 1, 1, true, None).unwrap();
        b.truncate(len);
        b
    }

    /// A NOERROR answer with one A record, TTL `ttl`.
    fn answer(req: &[u8], ttl: u32) -> Vec<u8> {
        let mut r = req.to_vec();
        r[2] |= 0x80; // QR
        r[7] = 1; // ANCOUNT
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
        r
    }

    // REQ: DNS-009 — a dump reloads into a fresh cache (re-keyed with a new seed); entries
    // that can't be served any more, and dumps from other routing, are left out.
    #[test]
    fn dns_009_dump_and_reload_survive_a_restart() {
        let now = Instant::now();
        let before = Cache::new(CachePolicy {
            serve_stale: false,
            ..CachePolicy::default()
        });
        let (seed_a, seed_b) = (11u64, 99u64);
        for (name, ttl) in [("keep.example", 3600), ("gone.example", 1)] {
            let req = query(name);
            let q = parse_query(&req).unwrap();
            let key = CacheKey::new(&q, q.qname.hash64(seed_a), 0);
            before.insert(&key, &q, &answer(&req, ttl), now).unwrap();
        }
        let mut dump = Vec::new();
        assert_eq!(
            before
                .dump(now + Duration::from_secs(5), 42, &mut dump)
                .unwrap(),
            2
        );

        let after = Cache::new(CachePolicy {
            serve_stale: false,
            ..CachePolicy::default()
        });
        let hash = |wire: &[u8]| {
            let mut n = NameBuf::default();
            telltale_proto::read_name_uncompressed(wire, 0, &mut n).ok()?;
            Some(n.hash64(seed_b))
        };
        assert!(
            after.load(&dump, now, 7, hash).is_err(),
            "another routing's dump"
        );
        assert_eq!(
            after.load(&dump, now, 42, hash).unwrap(),
            1,
            "the expired one is skipped"
        );
        let req = query("keep.example");
        let q = parse_query(&req).unwrap();
        let key = CacheKey::new(&q, q.qname.hash64(seed_b), 0);
        let mut out = vec![0u8; 512];
        let client = Client::from_query(&q, None);
        assert!(
            matches!(
                after.get(&key, &q.qname, &client, now, &mut out),
                crate::Lookup::Hit { .. }
            ),
            "served after reload"
        );
        assert!(after.load(b"nope", now, 42, hash).is_err());
    }
}
