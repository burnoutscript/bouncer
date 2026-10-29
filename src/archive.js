// Tar, gzip and zip readers. Packages are unpacked into memory and never
// written to disk or executed, so a malicious archive can't do anything here.

import { gunzipSync, inflateRawSync, createGunzip } from 'node:zlib';

export const LIMITS = {
  fileBytes: 8 * 1024 * 1024,
  totalBytes: 150 * 1024 * 1024,
  files: 20000,
};

const cstr = (buf, start, len) => {
  const end = buf.indexOf(0, start);
  return buf.toString('utf8', start, end === -1 || end > start + len ? start + len : end);
};

const octal = (buf, start, len) => parseInt(cstr(buf, start, len).trim() || '0', 8);

function safePath(p) {
  // Normalise and drop anything that tries to climb out (../ or absolute).
  return p.replace(/\\/g, '/').split('/').filter(s => s && s !== '.' && s !== '..').join('/');
}

export function readTar(buf) {
  const files = [];
  const skipped = [];
  let total = 0;
  let off = 0;
  let longName = null;
  let paxPath = null;

  while (off + 512 <= buf.length) {
    const header = buf.subarray(off, off + 512);
    if (header.every(b => b === 0)) break;

    const size = octal(header, 124, 12);
    const type = String.fromCharCode(header[156] || 48);
    const prefix = cstr(header, 345, 155);
    let name = cstr(header, 0, 100);
    if (prefix) name = `${prefix}/${name}`;
    const dataStart = off + 512;
    const data = buf.subarray(dataStart, dataStart + size);
    off = dataStart + Math.ceil(size / 512) * 512;

    if (type === 'L') { longName = cstr(data, 0, data.length); continue; }
    if (type === 'x') {
      const m = data.toString('utf8').match(/\d+ path=([^\n]*)\n/);
      if (m) paxPath = m[1];
      continue;
    }
    if (type === 'g') continue;

    const path = safePath(paxPath ?? longName ?? name);
    longName = paxPath = null;
    if (type !== '0' && type !== '\0' && type !== '7') continue;

    if (size > LIMITS.fileBytes || total + size > LIMITS.totalBytes || files.length >= LIMITS.files) {
      skipped.push({ path, size });
      continue;
    }
    total += size;
    files.push({ path, data: Buffer.from(data) });
  }
  return { files, skipped };
}

// Streaming version for big tarballs: entries over the limits are dropped as
// they stream past instead of being buffered.
export async function readTarGzStream(buf) {
  const files = [];
  const skipped = [];
  let total = 0;
  let pending = Buffer.alloc(0);
  let entry = null; // { path, size, remaining, keep, chunks, pad, meta }
  let longName = null;
  let paxPath = null;

  const onHeader = header => {
    const size = octal(header, 124, 12);
    const type = String.fromCharCode(header[156] || 48);
    const prefix = cstr(header, 345, 155);
    let name = cstr(header, 0, 100);
    if (prefix) name = `${prefix}/${name}`;
    const meta = type === 'L' || type === 'x' ? type : null;
    const isFile = type === '0' || type === '\0' || type === '7';
    const path = safePath(paxPath ?? longName ?? name);
    if (!meta) longName = paxPath = null;
    const keep = meta || (isFile && size <= LIMITS.fileBytes && total + size <= LIMITS.totalBytes && files.length < LIMITS.files);
    if (isFile && !keep) skipped.push({ path, size });
    if (keep && !meta) total += size;
    entry = { path, size, remaining: size, keep, chunks: [], pad: (512 - (size % 512)) % 512, meta, isFile };
  };

  const gunzip = createGunzip();
  gunzip.end(buf);
  for await (const chunk of gunzip) {
    pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
    let off = 0;
    while (true) {
      if (!entry) {
        if (pending.length - off < 512) break;
        const header = pending.subarray(off, off + 512);
        off += 512;
        if (header.every(b => b === 0)) continue;
        onHeader(header);
      }
      const take = Math.min(entry.remaining, pending.length - off);
      if (entry.keep && take > 0) entry.chunks.push(Buffer.from(pending.subarray(off, off + take)));
      off += take;
      entry.remaining -= take;
      if (entry.remaining > 0) break;
      if (pending.length - off < entry.pad) break;
      off += entry.pad;
      const data = Buffer.concat(entry.chunks);
      if (entry.meta === 'L') longName = cstr(data, 0, data.length);
      else if (entry.meta === 'x') { const m = data.toString('utf8').match(/\d+ path=([^\n]*)\n/); if (m) paxPath = m[1]; }
      else if (entry.keep && entry.isFile) files.push({ path: entry.path, data });
      entry = null;
    }
    pending = pending.subarray(off);
  }
  return { files, skipped };
}

export function readTarGz(buf) {
  return readTar(gunzipSync(buf, { maxOutputLength: LIMITS.totalBytes + 1024 * 1024 }));
}

export function readZip(buf) {
  const files = [];
  const skipped = [];
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd === -1) throw new Error('Not a zip file');

  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  let total = 0;

  for (let n = 0; n < count && p + 46 <= buf.length; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const path = safePath(buf.toString('utf8', p + 46, p + 46 + nameLen));
    p += 46 + nameLen + extraLen + commentLen;

    if (path.endsWith('/') || !path) continue;
    if (size > LIMITS.fileBytes || total + size > LIMITS.totalBytes || files.length >= LIMITS.files) {
      skipped.push({ path, size });
      continue;
    }
    const lNameLen = buf.readUInt16LE(local + 26);
    const lExtraLen = buf.readUInt16LE(local + 28);
    const start = local + 30 + lNameLen + lExtraLen;
    const raw = buf.subarray(start, start + compSize);
    let data;
    if (method === 0) data = Buffer.from(raw);
    else if (method === 8) data = inflateRawSync(raw, { maxOutputLength: LIMITS.fileBytes + 1 });
    else { skipped.push({ path, size, reason: `compression method ${method}` }); continue; }
    total += data.length;
    files.push({ path, data });
  }
  return { files, skipped };
}

export async function readArchive(buf, hint = '') {
  if (buf[0] === 0x1f && buf[1] === 0x8b) return readTarGzStream(buf);
  if (buf.readUInt32LE(0) === 0x04034b50 || /\.(whl|zip)$/i.test(hint)) return readZip(buf);
  return readTar(buf);
}

// npm tarballs wrap everything in "package/", sdists in "<name>-<version>/".
export function stripRoot(files) {
  const roots = new Set(files.map(f => f.path.split('/')[0]));
  if (roots.size !== 1 || files.every(f => !f.path.includes('/'))) return files;
  const [root] = roots;
  return files.map(f => ({ ...f, path: f.path.slice(root.length + 1) })).filter(f => f.path);
}
