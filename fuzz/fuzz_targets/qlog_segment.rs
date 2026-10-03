//! REQ: OBS-003, NFR-004 — the query-log segment reader must never panic, hang, or
//! over-allocate on any input (`spec/10` T3.2 "format fuzzed").
//!
//! The first byte picks a mode:
//! - 0: the bytes are a segment, read as-is.
//! - 1: the same, after recomputing every section checksum, so mutations reach the
//!   decompression and column-decoding paths instead of stopping at the checksum.
//! - 2: structure-aware: the bytes describe query events, which are encoded into a valid
//!   segment with the real writer; it must read back every row. Then trailing bytes are
//!   applied as XOR mutations, checksums repaired, and the result read again.
#![no_main]

use libfuzzer_sys::fuzz_target;
use telltale_store::qlog::format::repair_checksums;
use telltale_store::qlog::{reader, writer};
use telltale_telemetry::{Proto, QueryEvent, Status};

fn events(data: &[u8]) -> (Vec<(QueryEvent, Vec<u8>)>, &[u8]) {
    let n = usize::from(*data.first().unwrap_or(&0)).min(64);
    let mut rows = Vec::new();
    let mut rest = data.get(1..).unwrap_or_default();
    for i in 0..n {
        let Some((chunk, tail)) = rest.split_first_chunk::<8>() else { break };
        rest = tail;
        let label_len = usize::from(chunk[0] % 20) + 1;
        let mut name = vec![u8::try_from(label_len).unwrap()];
        name.extend((0..label_len).map(|j| b'a' + (chunk[1].wrapping_add(j as u8) % 26)));
        name.extend_from_slice(b"\x07example\x00");
        let mut ip = [0u8; 16];
        ip[15] = chunk[2] % 8;
        let ev = QueryEvent {
            ts_us: 1_790_000_000_000_000 + u64::from(u32::from_le_bytes([chunk[3], chunk[4], chunk[5], 0])),
            client_ip: ip,
            client_ref: u32::from(chunk[2]),
            group: u16::from(chunk[6] % 4),
            qtype: u16::from(chunk[7]),
            qclass: 1,
            rcode: (chunk[6] % 17 != 16).then_some(chunk[6] % 17),
            status: Status::ALL[usize::from(chunk[5]) % Status::ALL.len()],
            proto: Proto::ALL[i % 2],
            flags: u16::from_le_bytes([chunk[1], chunk[2]]),
            rule: None,
            upstream: u16::from(chunk[4] % 3),
            attempts: chunk[3] % 4,
            t_total_us: u32::from_le_bytes(*chunk.first_chunk::<4>().unwrap()),
            t_upstream_us: u32::from(chunk[7]),
            resp_size: u16::from(chunk[0]) * 3,
            answers: u16::from(chunk[1] % 9),
        };
        rows.push((ev, name));
    }
    (rows, rest)
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    match mode % 3 {
        0 => {
            let _ = reader::read_all(rest);
        }
        1 => {
            let mut seg = rest.to_vec();
            repair_checksums(&mut seg);
            let _ = reader::read_all(&seg);
        }
        _ => {
            let (rows, mutations) = events(rest);
            let Ok(mut seg) = writer::encode_in_memory(&rows, 497_222) else { return };
            let (_, n) = reader::read_all(&seg).expect("a freshly written segment reads back");
            assert_eq!(n, rows.len());
            if seg.is_empty() {
                return;
            }
            for pair in mutations.chunks_exact(3) {
                let at = usize::from(u16::from_le_bytes([pair[0], pair[1]])) % seg.len();
                seg[at] ^= pair[2] | 1;
            }
            repair_checksums(&mut seg);
            let _ = reader::read_all(&seg);
        }
    }
});
