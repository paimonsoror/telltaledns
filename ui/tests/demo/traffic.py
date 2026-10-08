#!/usr/bin/env python3
"""Synthetic traffic for the screenshot demo (run.sh): each made-up device asks its own mix of
names from its own loopback address, at a rate that rises and falls. 127.0.1.14 is left unnamed
on purpose, to show how an unknown device looks. usage: traffic.py <seconds>"""
import math
import random
import socket
import struct
import sys
import time

SERVER = ("127.0.0.1", 25353)
COMMON = ["www.google.com", "www.youtube.com", "i.ytimg.com", "www.apple.com", "github.com",
          "en.wikipedia.org", "api.spotify.com", "www.netflix.com", "fonts.gstatic.com",
          "cdn.jsdelivr.net", "www.bbc.co.uk", "news.ycombinator.com", "nas.home.arpa"]
ADS = ["googleads.g.doubleclick.net", "pagead2.googlesyndication.com", "app-measurement.com",
       "ads.example.com", "tracker.example.org"]
DEVICES = {
    "127.0.1.11": (3.0, COMMON + ["mail.example.com", "maps.example.com"], ADS, 0.12),
    "127.0.1.14": (1.2, COMMON, ADS, 0.10),
    "127.0.4.30": (4.0, COMMON + ["slack.example.com", "zoom.example.com", "docs.example.com",
                                  "login.example.com", "cdn.nx.example"], ["telemetry.example.net"], 0.08),
    "127.0.2.10": (2.5, ["www.youtube.com", "i.ytimg.com", "kids.example.com", "games.example.com",
                         "www.roblox.example"], ADS, 0.22),
    "127.0.2.12": (3.5, ["store.example.com", "cdn.games.example", "voice.example.com",
                         "update.games.example", "old.nx.example"], ADS, 0.10),
    "127.0.3.20": (2.0, ["www.netflix.com", "api.tv-vendor.example", "img.tv-vendor.example"],
                   ["metrics.tv-vendor.example"], 0.35),
    "127.0.3.21": (0.6, ["api.thermostat.example", "time.example.net"], ["telemetry.example.net"], 0.20),
    "127.0.3.22": (1.0, ["api.spotify.com", "speaker.example.com", "time.example.net"], [], 0.0),
}


def query(name: str) -> bytes:
    q = struct.pack(">HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)


socks = {}
for ip in DEVICES:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, 0))
    s.setblocking(False)
    socks[ip] = s

end = time.time() + float(sys.argv[1])
t0 = time.time()
sent = 0
while time.time() < end:
    t = time.time() - t0
    # A daily-looking swell: busier, then quieter, then busier again.
    level = 1.0 + 0.6 * math.sin(t / 90.0) + 0.3 * math.sin(t / 23.0)
    for ip, (rate, names, ads, ad_share) in DEVICES.items():
        n = rate * level * 0.25
        k = int(n) + (1 if random.random() < n - int(n) else 0)
        for _ in range(k):
            name = random.choice(ads) if ads and random.random() < ad_share else random.choice(names)
            socks[ip].sendto(query(name), SERVER)
            sent += 1
        try:
            while True:
                socks[ip].recv(4096)
        except BlockingIOError:
            pass
    time.sleep(0.25)
print("sent", sent)
