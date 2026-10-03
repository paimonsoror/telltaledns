//! OBS-002 / NFR-002: recording a query never allocates (own test binary, single test).

use std::time::Duration;

use telltale_telemetry::{Metrics, Proto, Status};

#[test]
fn obs_002_record_does_not_allocate() {
    let m = Metrics::new(1);
    m.record(Proto::Udp, Status::Cached, Some(0), 1, Duration::ZERO); // assigns this thread's slot
    let info = allocation_counter::measure(|| {
        for i in 0..10_000u16 {
            m.record(
                Proto::Udp,
                Status::Cached,
                Some(0),
                i % 300,
                Duration::from_micros(u64::from(i)),
            );
        }
    });
    assert_eq!(info.count_total, 0);
}
