//! NFR-004 / `09` §1: the list parser never panics, and what it emits is well-formed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use telltale_config::{ListKind, ListMatch};
use telltale_filter::parse::{ListOptions, Pattern, normalize, parse_list};

fuzz_target!(|data: &[u8]| {
    let Some((&flags, body)) = data.split_first() else {
        return;
    };
    let opts = ListOptions {
        kind: if flags & 1 == 0 { ListKind::Block } else { ListKind::Allow },
        match_mode: if flags & 2 == 0 { ListMatch::Subtree } else { ListMatch::Exact },
    };
    let mut rules = 0u64;
    let stats = parse_list(body, opts, |_, rule| {
        rules += 1;
        match &rule.pattern {
            // Emitted names are already normalized: normalizing again changes nothing.
            Pattern::Domain { name, .. } => {
                assert_eq!(normalize(name).as_deref(), Ok(name.as_str()), "{rule}");
            }
            Pattern::Regex { pattern, .. } => {
                assert!(regex_syntax::Parser::new().parse(pattern).is_ok(), "{rule}");
            }
        }
        for d in &rule.modifiers.denyallow {
            assert_eq!(normalize(d).as_deref(), Ok(d.as_str()));
        }
        let _ = rule.to_string();
    });
    assert_eq!(rules, stats.rules);
    assert_eq!(
        stats.lines,
        stats.blank + stats.comments + stats.ignored + stats.invalid + stats.unsupported
            + lines_with_rules(body, opts)
    );
});

/// Lines that produced at least one rule (hosts lines can produce several).
fn lines_with_rules(body: &[u8], opts: ListOptions) -> u64 {
    let mut last = 0u32;
    let mut n = 0;
    parse_list(body, opts, |line, _| {
        if line != last {
            n += 1;
            last = line;
        }
    });
    n
}
