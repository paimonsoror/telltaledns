//! Linux syscall layer: batched `recvmmsg`/`sendmmsg` with `IP_PKTINFO`/`IPV6_PKTINFO`.
//!
//! REQ: DNS-001, NFR-003. This is the only module in TelltaleDNS that contains `unsafe`.
//! All buffers are allocated once per worker at startup; the pointer tables handed to the
//! kernel are rebuilt before every call, so nothing is self-referential across moves.

// FFI glue: casts convert small compile-time sizes (struct sizes, batch caps <= 1024) and
// AF_* constants into C types. Some casts look redundant on glibc but are required on musl,
// where msghdr/cmsghdr field types differ (u32 vs usize).
#![allow(clippy::cast_possible_truncation, clippy::unnecessary_cast)]

use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;

use crate::udp::LocalAddr;

/// Max datagram size we accept from clients. Queries are small; anything larger is junk.
pub(crate) const RX_BUF: usize = 4096;
/// Max reply size we send over UDP (bounded by `udp_limit`, at most 4096 in practice).
pub(crate) const TX_BUF: usize = 4096;
/// Control-message buffer size: enough for one `in6_pktinfo` cmsg, 8-byte aligned.
const CTRL_WORDS: usize = 8;
type CtrlBuf = [u64; CTRL_WORDS];
const CTRL_LEN: usize = CTRL_WORDS * 8;

/// Raises the calling thread's nice value to at least `nice` (lower priority); a thread
/// that's already lower is left alone. On Linux, `setpriority(PRIO_PROCESS, tid)` applies to
/// that one thread, and threads it spawns inherit the value.
pub(crate) fn lower_thread_priority(nice: i32) -> io::Result<()> {
    // SAFETY: SYS_gettid takes no arguments and cannot fail.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    let tid = libc::id_t::try_from(tid).map_err(io::Error::other)?;
    // SAFETY: getpriority only reads its scalar arguments; `tid` is this thread's own ID.
    let cur = unsafe { libc::getpriority(libc::PRIO_PROCESS as _, tid) };
    let target = nice.clamp(-20, 19);
    if cur >= target {
        return Ok(());
    }
    // SAFETY: setpriority only reads its scalar arguments; `tid` is this thread's own ID.
    let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS as _, tid, target) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Dumps the kernel neighbor table over rtnetlink (FLT-006). Parsing is safe code in
/// `neigh`; this function only owns the socket.
pub(crate) fn neighbor_dump() -> io::Result<Vec<crate::neigh::Neighbor>> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: plain socket(2) call with constant arguments; the result is checked below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly created, valid descriptor that nothing else owns.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // A dump never takes long; don't let a wedged kernel reply hang the refresher.
    let tv = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a valid timeval and the length matches its size.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            ptr::addr_of!(tv).cast(),
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sockaddr_nl is plain old data; all-zero is a valid value (pid 0 = the kernel).
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let req = crate::neigh::dump_request(1);
    // SAFETY: `req` and `addr` outlive the call; the lengths match the buffers.
    let sent = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            req.as_ptr().cast(),
            req.len(),
            0,
            ptr::addr_of!(addr).cast(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        // SAFETY: `buf` is a valid, writable buffer of the given length.
        let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = usize::try_from(n).map_err(io::Error::other)?;
        if n == 0 {
            return Ok(out);
        }
        if crate::neigh::parse(&buf[..n], &mut out)? == crate::neigh::Chunk::Done {
            return Ok(out);
        }
    }
}

/// Enables destination-address reporting so replies can use the right source address.
pub(crate) fn enable_pktinfo(sock: &impl AsRawFd, v6: bool) -> io::Result<()> {
    let one: libc::c_int = 1;
    let (level, opt) = if v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    };
    // SAFETY: `one` is a valid c_int that outlives the call, and its exact size is passed.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            ptr::from_ref(&one).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// One received datagram's metadata.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RxMeta {
    pub(crate) len: usize,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) local: Option<LocalAddr>,
    pub(crate) truncated: bool,
}

/// Per-worker batch buffers for `recvmmsg` and `sendmmsg`.
pub(crate) struct Batch {
    cap: usize,
    rx: Box<[[u8; RX_BUF]]>,
    rx_addr: Box<[libc::sockaddr_storage]>,
    rx_ctrl: Box<[CtrlBuf]>,
    rx_iov: Box<[libc::iovec]>,
    rx_hdr: Box<[libc::mmsghdr]>,
    tx: Box<[[u8; TX_BUF]]>,
    tx_len: Box<[usize]>,
    tx_addr: Box<[libc::sockaddr_storage]>,
    tx_addr_len: Box<[libc::socklen_t]>,
    tx_ctrl: Box<[CtrlBuf]>,
    tx_ctrl_len: Box<[usize]>,
    tx_iov: Box<[libc::iovec]>,
    tx_hdr: Box<[libc::mmsghdr]>,
    tx_count: usize,
}

impl std::fmt::Debug for Batch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Batch")
            .field("cap", &self.cap)
            .field("tx_count", &self.tx_count)
            .finish_non_exhaustive()
    }
}

fn zeroed_box<T: Copy>(n: usize) -> Box<[T]> {
    // SAFETY: only instantiated with plain-old-data libc structs (sockaddr_storage, iovec,
    // mmsghdr) for which the all-zero bit pattern is a valid value.
    vec![unsafe { MaybeUninit::<T>::zeroed().assume_init() }; n].into_boxed_slice()
}

impl Batch {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap,
            rx: vec![[0u8; RX_BUF]; cap].into_boxed_slice(),
            rx_addr: zeroed_box(cap),
            rx_ctrl: vec![[0u64; CTRL_WORDS]; cap].into_boxed_slice(),
            rx_iov: zeroed_box(cap),
            rx_hdr: zeroed_box(cap),
            tx: vec![[0u8; TX_BUF]; cap].into_boxed_slice(),
            tx_len: vec![0; cap].into_boxed_slice(),
            tx_addr: zeroed_box(cap),
            tx_addr_len: vec![0; cap].into_boxed_slice(),
            tx_ctrl: vec![[0u64; CTRL_WORDS]; cap].into_boxed_slice(),
            tx_ctrl_len: vec![0; cap].into_boxed_slice(),
            tx_iov: zeroed_box(cap),
            tx_hdr: zeroed_box(cap),
            tx_count: 0,
        }
    }

    /// Receives up to `capacity()` datagrams, blocking until at least one arrives (or the
    /// socket's read timeout fires, which surfaces as `WouldBlock`). Returns the count.
    pub(crate) fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        for i in 0..self.cap {
            self.rx_iov[i] = libc::iovec {
                iov_base: self.rx[i].as_mut_ptr().cast(),
                iov_len: RX_BUF,
            };
            let h = &mut self.rx_hdr[i];
            h.msg_len = 0;
            h.msg_hdr.msg_name = ptr::from_mut(&mut self.rx_addr[i]).cast();
            h.msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            h.msg_hdr.msg_iov = ptr::from_mut(&mut self.rx_iov[i]);
            h.msg_hdr.msg_iovlen = 1;
            h.msg_hdr.msg_control = self.rx_ctrl[i].as_mut_ptr().cast();
            h.msg_hdr.msg_controllen = CTRL_LEN as _;
            h.msg_hdr.msg_flags = 0;
        }
        // SAFETY: every header points into buffers owned by `self` that stay alive and
        // unmoved for the duration of the call; lengths match the buffers; `cap` headers exist.
        let n = unsafe {
            libc::recvmmsg(
                fd,
                self.rx_hdr.as_mut_ptr(),
                self.cap as libc::c_uint,
                libc::MSG_WAITFORONE as _,
                ptr::null_mut(),
            )
        };
        usize::try_from(n).map_err(|_| io::Error::last_os_error())
    }

    /// Metadata for received datagram `i` (valid after `recv` returned more than `i`).
    pub(crate) fn rx_meta(&self, i: usize) -> RxMeta {
        let h = &self.rx_hdr[i];
        RxMeta {
            len: (h.msg_len as usize).min(RX_BUF),
            peer: sockaddr_to_std(&self.rx_addr[i], h.msg_hdr.msg_namelen),
            local: pktinfo_from_cmsgs(&h.msg_hdr),
            truncated: h.msg_hdr.msg_flags & libc::MSG_TRUNC != 0,
        }
    }

    /// Received datagram `i` (first `len` bytes) together with the next free send buffer.
    pub(crate) fn rx_and_next_tx(
        &mut self,
        i: usize,
        len: usize,
    ) -> (&[u8], Option<&mut [u8; TX_BUF]>) {
        (
            &self.rx[i][..len.min(RX_BUF)],
            self.tx.get_mut(self.tx_count),
        )
    }

    /// Queues the send buffer last returned by [`Batch::rx_and_next_tx`] (`len` bytes) for sending to
    /// `peer`, from `local` if known. Returns false if the send queue is full.
    pub(crate) fn queue_tx(
        &mut self,
        len: usize,
        peer: SocketAddr,
        local: Option<LocalAddr>,
    ) -> bool {
        let i = self.tx_count;
        if i >= self.cap {
            return false;
        }
        self.tx_len[i] = len.min(TX_BUF);
        self.tx_addr_len[i] = std_to_sockaddr(peer, &mut self.tx_addr[i]);
        self.tx_ctrl_len[i] = local.map_or(0, |l| write_pktinfo(&mut self.tx_ctrl[i], l));
        self.tx_count += 1;
        true
    }

    /// Sends all queued datagrams. Returns (sent, failed). Never blocks indefinitely on one
    /// bad destination: a failing message is skipped and counted.
    pub(crate) fn flush(&mut self, fd: RawFd) -> (usize, usize) {
        let count = self.tx_count;
        self.tx_count = 0;
        for i in 0..count {
            self.tx_iov[i] = libc::iovec {
                iov_base: self.tx[i].as_mut_ptr().cast(),
                iov_len: self.tx_len[i],
            };
            let h = &mut self.tx_hdr[i];
            h.msg_len = 0;
            h.msg_hdr.msg_name = ptr::from_mut(&mut self.tx_addr[i]).cast();
            h.msg_hdr.msg_namelen = self.tx_addr_len[i];
            h.msg_hdr.msg_iov = ptr::from_mut(&mut self.tx_iov[i]);
            h.msg_hdr.msg_iovlen = 1;
            h.msg_hdr.msg_control = if self.tx_ctrl_len[i] == 0 {
                ptr::null_mut()
            } else {
                self.tx_ctrl[i].as_mut_ptr().cast()
            };
            h.msg_hdr.msg_controllen = self.tx_ctrl_len[i] as _;
            h.msg_hdr.msg_flags = 0;
        }
        let (mut sent, mut failed, mut start) = (0, 0, 0);
        while start < count {
            // SAFETY: headers `start..count` point into buffers owned by `self`, alive and
            // unmoved for the call; `count - start` headers are initialized above.
            let n = unsafe {
                libc::sendmmsg(
                    fd,
                    self.tx_hdr[start..].as_mut_ptr(),
                    (count - start) as libc::c_uint,
                    0,
                )
            };
            match usize::try_from(n) {
                Ok(0) | Err(_) => {
                    let err = io::Error::last_os_error();
                    if n < 0 && err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    failed += 1;
                    start += 1;
                }
                Ok(k) => {
                    sent += k;
                    start += k;
                }
            }
        }
        (sent, failed)
    }
}

/// Sends one datagram (deferred replies from async tasks), with source address control.
pub(crate) fn send_one(
    fd: RawFd,
    buf: &[u8],
    peer: SocketAddr,
    local: Option<LocalAddr>,
) -> io::Result<usize> {
    // SAFETY: all-zero is a valid sockaddr_storage.
    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let addr_len = std_to_sockaddr(peer, &mut addr);
    let mut ctrl: CtrlBuf = [0; CTRL_WORDS];
    let ctrl_len = local.map_or(0, |l| write_pktinfo(&mut ctrl, l));
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr().cast_mut().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: all-zero is a valid msghdr; fields are set below.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = ptr::from_mut(&mut addr).cast();
    msg.msg_namelen = addr_len;
    msg.msg_iov = ptr::from_mut(&mut iov);
    msg.msg_iovlen = 1;
    if ctrl_len > 0 {
        msg.msg_control = ctrl.as_mut_ptr().cast();
        msg.msg_controllen = ctrl_len as _;
    }
    // SAFETY: `msg` points at stack values that outlive the call; the kernel only reads `buf`
    // (sendmsg never writes through iov_base).
    let n = unsafe { libc::sendmsg(fd, &raw const msg, 0) };
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}

fn sockaddr_to_std(s: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    let len = len as usize;
    match libc::c_int::from(s.ss_family) {
        libc::AF_INET if len >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: family is AF_INET and the kernel wrote at least sizeof(sockaddr_in)
            // bytes; sockaddr_storage is suitably aligned for any sockaddr type.
            let a: libc::sockaddr_in = unsafe { ptr::read(ptr::from_ref(s).cast()) };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 if len >= mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: as above, for AF_INET6 / sockaddr_in6.
            let a: libc::sockaddr_in6 = unsafe { ptr::read(ptr::from_ref(s).cast()) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

fn std_to_sockaddr(addr: SocketAddr, out: &mut libc::sockaddr_storage) -> libc::socklen_t {
    match addr {
        SocketAddr::V4(a) => {
            // SAFETY: all-zero is a valid sockaddr_in.
            let mut s: libc::sockaddr_in = unsafe { mem::zeroed() };
            s.sin_family = libc::AF_INET as libc::sa_family_t;
            s.sin_port = a.port().to_be();
            s.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            // SAFETY: sockaddr_storage is large and aligned enough for sockaddr_in.
            unsafe { ptr::write(ptr::from_mut(out).cast(), s) };
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(a) => {
            // SAFETY: all-zero is a valid sockaddr_in6.
            let mut s: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            s.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            s.sin6_port = a.port().to_be();
            s.sin6_addr.s6_addr = a.ip().octets();
            s.sin6_flowinfo = a.flowinfo();
            s.sin6_scope_id = a.scope_id();
            // SAFETY: sockaddr_storage is large and aligned enough for sockaddr_in6.
            unsafe { ptr::write(ptr::from_mut(out).cast(), s) };
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

/// Extracts the destination address/interface from IP(V6)_PKTINFO control messages.
fn pktinfo_from_cmsgs(msg: &libc::msghdr) -> Option<LocalAddr> {
    if msg.msg_control.is_null() || (msg.msg_controllen as usize) < mem::size_of::<libc::cmsghdr>()
    {
        return None;
    }
    // SAFETY: `msg` was filled in by recvmmsg; msg_control/msg_controllen describe a buffer
    // we own, and the CMSG_* macros only walk within that length.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is non-null and within the control buffer (CMSG_FIRSTHDR/NXTHDR).
        let c = unsafe { &*cmsg };
        if c.cmsg_level == libc::IPPROTO_IP && c.cmsg_type == libc::IP_PKTINFO {
            // SAFETY: the kernel wrote an in_pktinfo payload for this cmsg type; it may be
            // unaligned, so read_unaligned.
            let info: libc::in_pktinfo =
                unsafe { ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast()) };
            return Some(LocalAddr {
                ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr))),
                ifindex: u32::try_from(info.ipi_ifindex).unwrap_or(0),
            });
        }
        if c.cmsg_level == libc::IPPROTO_IPV6 && c.cmsg_type == libc::IPV6_PKTINFO {
            // SAFETY: as above, for in6_pktinfo.
            let info: libc::in6_pktinfo =
                unsafe { ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast()) };
            return Some(LocalAddr {
                ip: IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)),
                ifindex: info.ipi6_ifindex,
            });
        }
        // SAFETY: `msg` and `cmsg` are valid as established above.
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    None
}

/// Writes a PKTINFO cmsg selecting the reply's source address. Returns the control length.
fn write_pktinfo(buf: &mut CtrlBuf, local: LocalAddr) -> usize {
    // A fake msghdr so CMSG_FIRSTHDR can locate the first header in `buf`.
    // SAFETY: all-zero is a valid msghdr.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_control = buf.as_mut_ptr().cast();
    msg.msg_controllen = CTRL_LEN as _;
    // SAFETY: `buf` is CTRL_LEN bytes, 8-byte aligned, and large enough for one cmsghdr plus
    // an in6_pktinfo (CMSG_SPACE(20) = 40 <= 64).
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        if cmsg.is_null() {
            return 0;
        }
        match local.ip {
            IpAddr::V4(ip) => {
                let mut info: libc::in_pktinfo = mem::zeroed();
                info.ipi_spec_dst.s_addr = u32::from(ip).to_be();
                (*cmsg).cmsg_level = libc::IPPROTO_IP;
                (*cmsg).cmsg_type = libc::IP_PKTINFO;
                (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as u32) as _;
                ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), info);
                libc::CMSG_SPACE(mem::size_of::<libc::in_pktinfo>() as u32) as usize
            }
            IpAddr::V6(ip) => {
                let mut info: libc::in6_pktinfo = mem::zeroed();
                info.ipi6_addr.s6_addr = ip.octets();
                info.ipi6_ifindex = local.ifindex;
                (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::in6_pktinfo>() as u32) as _;
                ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), info);
                libc::CMSG_SPACE(mem::size_of::<libc::in6_pktinfo>() as u32) as usize
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_001_sockaddr_roundtrip() {
        for addr in [
            "192.0.2.7:5353".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:53".parse().unwrap(),
        ] {
            // SAFETY: all-zero is a valid sockaddr_storage.
            let mut s: libc::sockaddr_storage = unsafe { mem::zeroed() };
            let len = std_to_sockaddr(addr, &mut s);
            assert_eq!(sockaddr_to_std(&s, len), Some(addr));
        }
    }

    #[test]
    fn dns_001_pktinfo_cmsg_roundtrip() {
        for ip in [
            "10.1.2.3".parse::<IpAddr>().unwrap(),
            "fe80::1".parse().unwrap(),
        ] {
            let mut buf: CtrlBuf = [0; CTRL_WORDS];
            let local = LocalAddr { ip, ifindex: 3 };
            let len = write_pktinfo(&mut buf, local);
            assert!(len > 0 && len <= CTRL_LEN);
            // SAFETY: all-zero is a valid msghdr.
            let mut msg: libc::msghdr = unsafe { mem::zeroed() };
            msg.msg_control = buf.as_mut_ptr().cast();
            msg.msg_controllen = len as _;
            // The send path writes ipi_spec_dst; the receive path reads ipi_addr, so for v4
            // only check that a header of the right type is present.
            let got = pktinfo_from_cmsgs(&msg);
            assert!(got.is_some());
            if ip.is_ipv6() {
                assert_eq!(got.unwrap().ip, ip);
            }
        }
    }
}
