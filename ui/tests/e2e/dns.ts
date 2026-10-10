import dgram from 'node:dgram';

/** Sends one DNS query over UDP to the test server; resolves with the response code. */
export function query(name: string, qtype = 1, port = 15354, from?: string): Promise<number> {
  const id = Math.floor(Math.random() * 0xffff);
  const qname = name.split('.').flatMap((l) => [l.length, ...Buffer.from(l)]);
  const msg = Buffer.from([id >> 8, id & 0xff, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...qname, 0, qtype >> 8, qtype & 0xff, 0, 1]);
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket('udp4');
    const t = setTimeout(() => {
      s.close();
      reject(new Error(`no answer for ${name}`));
    }, 3000);
    s.on('message', (m) => {
      clearTimeout(t);
      s.close();
      resolve(m[3] & 0x0f);
    });
    // `from`: another loopback address, to look like another device.
    if (from) s.bind({ address: from }, () => s.send(msg, port, '127.0.0.1'));
    else s.send(msg, port, '127.0.0.1');
  });
}
