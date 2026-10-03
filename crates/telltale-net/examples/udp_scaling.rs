//! T1.2 AC: multi-core scaling of the UDP workers (≥ 3.2× qps at 4 workers vs 1).
//!
//! Each query costs a fixed amount of CPU in the handler (standing in for the pipeline), so the
//! server is the bottleneck rather than the in-process load generator. The question this
//! answers is whether workers scale without contending with each other.
//!
//! Run: `cargo run --release -p telltale-net --example udp_scaling -- [work_us] [secs]`

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::hint::black_box;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use telltale_net::{Datagram, UdpConfig, UdpListener};

const GEN_THREADS: usize = 3;
const SOCKETS_PER_THREAD: usize = 32;
const WINDOW: u32 = 8;

fn busy_work(iters: u64, seed: u64) -> u64 {
    let mut x = seed | 1;
    for _ in 0..iters {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
    }
    x
}

fn calibrate(target_us: u64) -> u64 {
    let iters = 1_000_000;
    let t = Instant::now();
    black_box(busy_work(iters, 7));
    let ns_per_iter = t.elapsed().as_nanos() as f64 / iters as f64;
    ((target_us as f64 * 1000.0) / ns_per_iter) as u64
}

fn run(workers: usize, iters: u64, secs: u64) -> f64 {
    let handler = move |d: &Datagram<'_>, out: &mut [u8]| -> Option<usize> {
        let n = d.data.len().min(out.len());
        out[..n].copy_from_slice(&d.data[..n]);
        out[0] |= black_box(busy_work(iters, u64::from(d.data[1])) as u8);
        Some(n)
    };
    let listener = UdpListener::spawn(
        &UdpConfig::new("127.0.0.1:0".parse().unwrap(), workers),
        &Arc::new(handler),
    )
    .unwrap();
    let server = listener.local_addr();
    let stop = Arc::new(AtomicBool::new(false));
    let replies = Arc::new(AtomicU64::new(0));
    let gens: Vec<_> = (0..GEN_THREADS)
        .map(|_| {
            let (stop, replies) = (Arc::clone(&stop), Arc::clone(&replies));
            std::thread::spawn(move || generator(server, &stop, &replies))
        })
        .collect();
    std::thread::sleep(Duration::from_millis(500)); // warm-up
    let start_count = replies.load(Ordering::Relaxed);
    let t = Instant::now();
    std::thread::sleep(Duration::from_secs(secs));
    let qps = (replies.load(Ordering::Relaxed) - start_count) as f64 / t.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    for g in gens {
        g.join().unwrap();
    }
    listener.shutdown();
    qps
}

fn generator(server: SocketAddr, stop: &AtomicBool, replies: &AtomicU64) {
    let socks: Vec<UdpSocket> = (0..SOCKETS_PER_THREAD)
        .map(|_| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.set_nonblocking(true).unwrap();
            s.connect(server).unwrap();
            s
        })
        .collect();
    let mut outstanding = vec![0u32; socks.len()];
    let mut last_progress = vec![Instant::now(); socks.len()];
    let req = [0u8, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let mut buf = [0u8; 64];
    while !stop.load(Ordering::Relaxed) {
        for (i, s) in socks.iter().enumerate() {
            // Lost packets would stall a window forever; reset after 200 ms of silence.
            if outstanding[i] > 0 && last_progress[i].elapsed() > Duration::from_millis(200) {
                outstanding[i] = 0;
            }
            while outstanding[i] < WINDOW && s.send(&req).is_ok() {
                outstanding[i] += 1;
            }
            while s.recv(&mut buf).is_ok() {
                outstanding[i] = outstanding[i].saturating_sub(1);
                last_progress[i] = Instant::now();
                replies.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let work_us: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(20);
    let secs: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(3);
    let iters = calibrate(work_us);
    println!("per-query work ≈ {work_us} µs ({iters} iters); {GEN_THREADS} generator threads");
    let base = run(1, iters, secs);
    println!("workers=1  {base:>10.0} qps");
    let mut last = 0.0;
    for w in [2, 4] {
        last = run(w, iters, secs);
        println!("workers={w}  {last:>10.0} qps  ({:.2}×)", last / base);
    }
    let ratio = last / base;
    println!(
        "scaling 4 vs 1: {ratio:.2}× (AC: ≥ 3.20×) {}",
        if ratio >= 3.2 { "PASS" } else { "FAIL" }
    );
    if ratio < 3.2 {
        std::process::exit(1);
    }
}
