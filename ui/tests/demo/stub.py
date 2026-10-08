#!/usr/bin/env python3
"""Stub upstreams for the screenshot demo (run.sh): answer every A query with a TEST-NET address
(RFC 5737) after a small random delay; names under nx.example get NXDOMAIN, other types an empty
answer. usage: stub.py <port> <min_ms> <max_ms>"""
import asyncio
import random
import sys

port, lo, hi = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])


def answer(q: bytes) -> bytes | None:
    if len(q) < 17:
        return None
    end = 12
    labels = []
    while end < len(q) and q[end] != 0:
        n = q[end]
        labels.append(q[end + 1:end + 1 + n].decode("ascii", "replace").lower())
        end += n + 1
    end += 5
    if end > len(q):
        return None
    name = ".".join(labels)
    qtype = int.from_bytes(q[end - 4:end - 2], "big")
    nx = name.endswith("nx.example")
    flags = b"\x81\x83" if nx else b"\x81\x80"
    if nx or qtype != 1:
        return q[:2] + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00" + q[12:end]
    ip = bytes([198, 51, 100, (sum(name.encode()) % 250) + 1])
    rr = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + ip
    return q[:2] + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:end] + rr


class Proto(asyncio.DatagramProtocol):
    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        r = answer(data)
        if r is not None:
            asyncio.get_running_loop().call_later(
                random.uniform(lo, hi) / 1000, self.t.sendto, r, addr
            )


async def main():
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(Proto, local_addr=("127.0.0.1", port))
    await asyncio.Event().wait()


asyncio.run(main())
