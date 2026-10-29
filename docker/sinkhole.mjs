// Fake internet for the sandbox. Every DNS name resolves to 127.0.0.1, and
// TCP listeners on common ports record what the package tried to send.
// Writes one JSON object per line to /out/net.log.

import dgram from 'node:dgram';
import net from 'node:net';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';

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

// HTTPS: mint a certificate for each requested host, signed by the sandbox CA
// that the image trusts, so we can read what was sent.
const certs = new Map();
function contextFor(host) {
  if (!/^[a-z0-9.-]{1,253}$/i.test(host)) host = 'invalid.local';
  if (certs.has(host)) return certs.get(host);
  const dir = mkdtempSync('/tmp/cert-');
  writeFileSync(`${dir}/ext`, `subjectAltName=DNS:${host}\n`);
  execFileSync('openssl', ['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', `${dir}/key`, '-subj', `/CN=${host}`, '-out', `${dir}/csr`], { stdio: 'ignore' });
  execFileSync('openssl', ['x509', '-req', '-in', `${dir}/csr`, '-CA', '/etc/bouncer/ca.crt', '-CAkey', '/etc/bouncer/ca.key', '-CAcreateserial', '-days', '2', '-extfile', `${dir}/ext`, '-out', `${dir}/crt`], { stdio: 'ignore' });
  const pair = { key: readFileSync(`${dir}/key`), cert: readFileSync(`${dir}/crt`) };
  pair.ctx = tls.createSecureContext(pair);
  certs.set(host, pair);
  return pair;
}

const fallback = contextFor('localhost');
for (const port of [443, 8443]) {
  tls.createServer({
    key: fallback.key,
    cert: fallback.cert,
    SNICallback: (name, cb) => { try { cb(null, contextFor(name).ctx); } catch (e) { cb(e); } },
  }, sock => {
    const chunks = [];
    let size = 0;
    sock.on('data', d => {
      if (size < 16384) { chunks.push(d); size += d.length; }
      sock.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
    });
    sock.on('close', () => {
      const data = Buffer.concat(chunks);
      log({ kind: 'tcp', tls: true, port, sni: sock.servername || null, bytes: data.length, preview: data.toString('latin1', 0, 4096) });
    });
    sock.on('error', () => {});
    setTimeout(() => sock.destroy(), 3000);
  }).on('tlsClientError', (e, s) => {
    log({ kind: 'tcp', tls: true, port, sni: s.servername || null, bytes: 0, preview: '', error: e.code || e.message });
  }).listen(port, '127.0.0.1');
}

for (const port of [80, 8080, 3000, 4444, 5000, 8000, 8888, 9000]) {
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
