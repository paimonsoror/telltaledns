//! NFR-004: walking untrusted upstream responses (cache insert, CNAME inspection, patching).
#![no_main]

use libfuzzer_sys::fuzz_target;
use telltale_proto::{NameBuf, patch_ttls, read_name, records, rtype, summarize, truncate_for_udp};

fuzz_target!(|data: &[u8]| {
    let _ = summarize(data);
    let mut offsets = [0u16; 64];
    let mut n = 0;
    if let Ok(iter) = records(data) {
        for r in iter {
            let Ok(r) = r else { break };
            let _ = r.rdata(data);
            if !r.is_opt() && n < offsets.len() {
                if let Ok(off) = u16::try_from(r.ttl_off) {
                    offsets[n] = off;
                    n += 1;
                }
            }
            if r.rtype == rtype::CNAME {
                let mut target = NameBuf::default();
                let _ = read_name(data, r.rdata_off, &mut target);
            }
            let mut owner = NameBuf::default();
            let _ = read_name(data, r.name_off, &mut owner);
        }
    }
    let mut copy = data.to_vec();
    patch_ttls(&mut copy, &offsets[..n], 30, 0);
    let len = copy.len();
    let _ = truncate_for_udp(&mut copy, len, 512);
});
