//! pkt-line framing (Git's wire format): a 4-hex-digit length that includes itself, then the
//! data; `0000` flush, `0001` delimiter, `0002` response end.

/// One packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pkt {
    Data(Vec<u8>),
    Flush,
    Delim,
    End,
}

/// Encodes one data line.
pub fn line(data: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", data.len() + 4).into_bytes();
    out.extend_from_slice(data);
    out
}

pub const FLUSH: &[u8] = b"0000";
pub const DELIM: &[u8] = b"0001";

/// Splits a response into packets.
pub fn parse(mut b: &[u8]) -> Result<Vec<Pkt>, String> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let head = b.get(..4).ok_or("truncated pkt-line length")?;
        let s = std::str::from_utf8(head).map_err(|_| "bad pkt-line length")?;
        let n = usize::from_str_radix(s, 16).map_err(|_| format!("bad pkt-line length {s:?}"))?;
        match n {
            0 => out.push(Pkt::Flush),
            1 => out.push(Pkt::Delim),
            2 => out.push(Pkt::End),
            3 => return Err("bad pkt-line length 3".into()),
            n => {
                let data = b.get(4..n).ok_or("truncated pkt-line")?;
                out.push(Pkt::Data(data.to_vec()));
                b = &b[n..];
                continue;
            }
        }
        b = &b[4..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkt_lines_round_trip() {
        let mut b = line(b"command=ls-refs\n");
        b.extend_from_slice(DELIM);
        b.extend(line(b"peel\n"));
        b.extend_from_slice(FLUSH);
        assert_eq!(&b[..4], b"0014");
        let p = parse(&b).unwrap();
        assert_eq!(
            p,
            vec![
                Pkt::Data(b"command=ls-refs\n".to_vec()),
                Pkt::Delim,
                Pkt::Data(b"peel\n".to_vec()),
                Pkt::Flush
            ]
        );
        assert!(parse(b"00").is_err());
        assert!(parse(b"0009abc").is_err());
    }
}
