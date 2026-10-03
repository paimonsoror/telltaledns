#!/usr/bin/env python3
"""Fake authoritative upstream for the bench harness (spec/09 §2).

Answers every A/AAAA question with a deterministic address derived from the name
(TTL 3600, AA set), everything else with NODATA + SOA so negative answers are
cacheable (RFC 2308). An optional fixed delay stands in for netem.

Python on purpose: the stub only sees cache misses, and keeping it out of the Rust
workspace keeps the bench free of server code paths under test.
"""

import argparse
import asyncio
import hashlib
import signal
import struct
import sys

TTL = 3600
# RFC 2606/6761 style SOA for the synthetic zone; only used in negative answers.
SOA_RDATA = (
    b"\x02ns\x05bench\x04test\x00"
    b"\x0ahostmaster\x05bench\x04test\x00"
    + struct.pack("!IIIII", 1, 3600, 600, 86400, 300)
)


def parse_question(msg: bytes):
    """Returns (id, flags, qname_wire, qtype, qclass, end) or None if malformed."""
    if len(msg) < 12:
        return None
    qid, flags, qdcount = struct.unpack_from("!HHH", msg, 0)
    if qdcount != 1 or flags & 0x8000:
        return None
    pos = 12
    while True:
        if pos >= len(msg):
            return None
        n = msg[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0:
            return None
        pos += 1 + n
    if pos + 4 > len(msg):
        return None
    qtype, qclass = struct.unpack_from("!HH", msg, pos)
    return qid, flags, msg[12:pos], qtype, qclass, pos + 4


def answer(msg: bytes):
    q = parse_question(msg)
    if q is None:
        return None
    qid, qflags, qname, qtype, qclass, qend = q
    rd = qflags & 0x0100
    flags = 0x8000 | 0x0400 | rd  # QR, AA, copy RD; NOERROR
    question = msg[12:qend]
    digest = hashlib.blake2b(qname.lower(), digest_size=16).digest()
    if qtype == 1:  # A: 198.18.0.0/15 (RFC 2544 benchmarking range)
        rdata = bytes([198, 18 + (digest[0] & 1), digest[1], digest[2]])
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, qclass, TTL, 4) + rdata
        return struct.pack("!HHHHHH", qid, flags, 1, 1, 0, 0) + question + rr
    if qtype == 28:  # AAAA: 2001:2::/48 (RFC 5180 benchmarking range)
        rdata = b"\x20\x01\x00\x02\x00\x00" + digest[:10]
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 28, qclass, TTL, 16) + rdata
        return struct.pack("!HHHHHH", qid, flags, 1, 1, 0, 0) + question + rr
    soa = b"\xc0\x0c" + struct.pack("!HHIH", 6, qclass, 300, len(SOA_RDATA)) + SOA_RDATA
    return struct.pack("!HHHHHH", qid, flags, 1, 0, 1, 0) + question + soa


class Udp(asyncio.DatagramProtocol):
    def __init__(self, delay: float):
        self.delay = delay
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        resp = answer(data)
        if resp is None:
            return
        if self.delay:
            asyncio.get_running_loop().call_later(self.delay, self.transport.sendto, resp, addr)
        else:
            self.transport.sendto(resp, addr)


async def tcp_conn(reader, writer, delay):
    try:
        while True:
            hdr = await reader.readexactly(2)
            msg = await reader.readexactly(struct.unpack("!H", hdr)[0])
            resp = answer(msg)
            if resp is None:
                break
            if delay:
                await asyncio.sleep(delay)
            writer.write(struct.pack("!H", len(resp)) + resp)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()


async def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--addr", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5301)
    ap.add_argument("--delay-ms", type=float, default=0.0)
    args = ap.parse_args()
    delay = args.delay_ms / 1000.0

    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(lambda: Udp(delay), local_addr=(args.addr, args.port))
    tcp = await asyncio.start_server(lambda r, w: tcp_conn(r, w, delay), args.addr, args.port)
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    print(f"stub upstream on {args.addr}:{args.port} (delay {args.delay_ms} ms)", file=sys.stderr, flush=True)
    await stop.wait()
    udp.close()
    tcp.close()


if __name__ == "__main__":
    asyncio.run(main())
