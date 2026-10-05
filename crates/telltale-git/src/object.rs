//! Commit and tree objects.

/// A parsed commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub tree: String,
    pub parents: Vec<String>,
    /// `Name <email>`.
    pub author: String,
    /// Committer time, Unix seconds.
    pub time: i64,
    /// The `gpgsig` header (an SSH or PGP signature), if signed.
    pub signature: Option<String>,
    /// The commit as signed: the object without its `gpgsig` header.
    pub signed_payload: Vec<u8>,
    /// First line of the message.
    pub subject: String,
}

/// Parses a commit object.
pub fn commit(data: &[u8]) -> Result<Commit, String> {
    let text = std::str::from_utf8(data).map_err(|_| "commit isn't UTF-8")?;
    let (head, message) = text.split_once("\n\n").unwrap_or((text, ""));
    let mut c = Commit {
        tree: String::new(),
        parents: Vec::new(),
        author: String::new(),
        time: 0,
        signature: None,
        signed_payload: Vec::with_capacity(data.len()),
        subject: message.lines().next().unwrap_or("").to_owned(),
    };
    let mut in_sig = false;
    let mut sig = String::new();
    for line in head.split('\n') {
        if in_sig {
            if let Some(rest) = line.strip_prefix(' ') {
                sig.push('\n');
                sig.push_str(rest);
                continue;
            }
            in_sig = false;
        }
        if let Some(v) = line.strip_prefix("gpgsig ") {
            in_sig = true;
            sig.push_str(v);
            continue;
        }
        c.signed_payload.extend_from_slice(line.as_bytes());
        c.signed_payload.push(b'\n');
        if let Some(v) = line.strip_prefix("tree ") {
            v.clone_into(&mut c.tree);
        } else if let Some(v) = line.strip_prefix("parent ") {
            c.parents.push(v.to_owned());
        } else if let Some(v) = line.strip_prefix("author ") {
            if let Some(end) = v.find('>') {
                v[..=end].clone_into(&mut c.author);
            }
        } else if let Some(v) = line.strip_prefix("committer ") {
            c.time = v
                .rsplit(' ')
                .nth(1)
                .and_then(|t| t.parse().ok())
                .unwrap_or(0);
        }
    }
    c.signed_payload.push(b'\n');
    c.signed_payload.extend_from_slice(message.as_bytes());
    if !sig.is_empty() {
        c.signature = Some(sig);
    }
    if c.tree.len() != 40 {
        return Err("commit has no tree".into());
    }
    Ok(c)
}

/// One tree entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub mode: String,
    pub name: String,
    pub oid: String,
}

impl Entry {
    pub fn is_tree(&self) -> bool {
        self.mode == "40000"
    }
}

/// Parses a tree object.
pub fn tree(mut data: &[u8]) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let sp = data
            .iter()
            .position(|&b| b == b' ')
            .ok_or("bad tree entry")?;
        let nul = data.iter().position(|&b| b == 0).ok_or("bad tree entry")?;
        if nul < sp || data.len() < nul + 21 {
            return Err("bad tree entry".into());
        }
        out.push(Entry {
            mode: String::from_utf8_lossy(&data[..sp]).into_owned(),
            name: String::from_utf8_lossy(&data[sp + 1..nul]).into_owned(),
            oid: crate::pack::hex(&data[nul + 1..nul + 21]),
        });
        data = &data[nul + 21..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commits_parse_and_strip_their_signature() {
        let raw = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nparent 1111111111111111111111111111111111111111\nauthor Ada <ada@example.com> 1791000000 +0000\ncommitter Ada <ada@example.com> 1791000001 +0000\ngpgsig -----BEGIN SSH SIGNATURE-----\n AAAA\n -----END SSH SIGNATURE-----\n\nAdd blocklist\n\nmore\n";
        let c = commit(raw.as_bytes()).unwrap();
        assert_eq!(c.parents.len(), 1);
        assert_eq!(c.author, "Ada <ada@example.com>");
        assert_eq!(c.time, 1_791_000_001);
        assert_eq!(c.subject, "Add blocklist");
        assert_eq!(
            c.signature.as_deref(),
            Some("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----")
        );
        let payload = String::from_utf8(c.signed_payload).unwrap();
        assert!(!payload.contains("gpgsig") && payload.ends_with("\n\nAdd blocklist\n\nmore\n"));
    }
}
