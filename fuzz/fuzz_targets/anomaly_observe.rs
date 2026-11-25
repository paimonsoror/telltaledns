//! REQ: OBS-009, NFR-004 — the anomaly engine takes any wire bytes: names with any bytes (and bytes
//! that are not a name at all), any answer code, a few devices, and times that move on, step back,
//! or jump hours ahead. An NXDOMAIN storm's detail stays bounded: at most five sample names of at
//! most 64 bytes each.
#![no_main]

use libfuzzer_sys::fuzz_target;
use telltale_telemetry::anomaly::{Engine, Kind, Settings};

/// A time in 2026, in microseconds.
const START_US: u64 = 1_790_000_000_000_000;

fuzz_target!(|data: &[u8]| {
    let mut engine = Engine::new(Settings::default());
    let mut at_us = START_US;
    let mut rest = data;
    // Each query: four bytes (name length, answer code, device, time step), then the name.
    while let Some((&[len, code, device, step], tail)) = rest.split_first_chunk::<4>() {
        let (wire, after) = tail.split_at(usize::from(len).min(tail.len()));
        rest = after;
        let rcode = match code % 4 {
            0 | 1 => Some(3),
            2 => None,
            _ => Some(code >> 2),
        };
        let mut client = [0u8; 16];
        client[10] = 0xff;
        client[11] = 0xff;
        client[15] = device % 8;
        at_us = match step {
            0..=223 => at_us.saturating_add(u64::from(step) * 100_000),
            224..=239 => at_us.saturating_sub(u64::from(step - 223) * 60_000_000),
            _ => at_us.saturating_add(u64::from(step - 239) * 3_600_000_000),
        };
        engine.observe_query(at_us, client, wire, rcode);
    }
    // A later query from another device closes the last minute and hour.
    engine.observe_answer(
        at_us / 1_000_000 + 7200,
        [0; 16],
        b"\x01x\x07example\x00",
        Some(0),
    );
    for f in engine.findings() {
        if f.kind == Kind::NxdomainStorm {
            assert!(f.detail.len() <= 512, "{}", f.detail);
        }
    }
});
