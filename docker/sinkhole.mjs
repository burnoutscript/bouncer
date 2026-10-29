// Fake internet for the sandbox. Every DNS name resolves to 127.0.0.1, and
// TCP listeners on common ports record what the package tried to send.
// Writes one JSON object per line to /out/net.log.

import dgram from 'node:dgram';
import net from 'node:net';
import { appendFileSync } from 'node:fs';

const LOG = process.env.SINK_LOG || '/out/net.log';
const log = o => appendFileSync(LOG, JSON.stringify({ t: Date.now(), ...o }) + '\n');

function qname(msg, off) {
  const labels = [];
  while (off < msg.length && msg[off] !== 0) {
    const len = msg[off];
    labels.push(msg.toString('latin1', off + 1, off + 1 + len));
    off += len + 1;
  }
  return { name: labels.join('.'), end: off + 1 };
}

const dns = dgram.createSocket('udp4');
dns.on('message', (msg, rinfo) => {
  if (msg.length < 12) return;
  const { name, end } = qname(msg, 12);
  const qtype = msg.readUInt16BE(end);
  log({ kind: 'dns', name, qtype });
  const question = msg.subarray(12, end + 4);
  const isA = qtype === 1;
  const header = Buffer.from(msg.subarray(0, 12));
  header.writeUInt16BE(0x8180, 2); // response, recursion available, no error
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(isA ? 1 : 0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);
  const answer = isA ? Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]) : Buffer.alloc(0);
  dns.send(Buffer.concat([header, question, answer]), rinfo.port, rinfo.address);
});
dns.bind(53, '127.0.0.1');

// TLS ClientHello: pull the SNI hostname out so we know where HTTPS was headed.
function sni(buf) {
  try {
    if (buf[0] !== 0x16) return null;
    let p = 5 + 4 + 2 + 32;
    p += 1 + buf[p];
    p += 2 + buf.readUInt16BE(p);
    p += 1 + buf[p];
    const extEnd = p + 2 + buf.readUInt16BE(p);
    p += 2;
    while (p + 4 <= extEnd) {
      const type = buf.readUInt16BE(p);
      const len = buf.readUInt16BE(p + 2);
      if (type === 0) return buf.toString('latin1', p + 9, p + 9 + buf.readUInt16BE(p + 7));
      p += 4 + len;
    }
  } catch { /* not a full ClientHello */ }
  return null;
}

for (const port of [80, 443, 8080, 8443, 3000, 4444, 5000, 8000, 8888, 9000]) {
  net.createServer(sock => {
    const chunks = [];
    let size = 0;
    sock.on('data', d => {
      if (size < 16384) { chunks.push(d); size += d.length; }
      if (port === 80 || port === 8080 || port === 3000 || port === 5000 || port === 8000) {
        sock.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
      }
    });
    const done = () => {
      const data = Buffer.concat(chunks);
      log({ kind: 'tcp', port, sni: sni(data), bytes: data.length, preview: data.toString('latin1', 0, 4096) });
    };
    sock.on('close', done);
    sock.on('error', () => {});
    setTimeout(() => sock.destroy(), 3000);
  }).listen(port, '127.0.0.1');
}
