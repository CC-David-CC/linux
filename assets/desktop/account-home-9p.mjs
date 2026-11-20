// 9P2000.L account-home filesystem for the browser-owned VirtIO device.
// The guest never receives the account credential or the server's data path.
const HEADER = 7;
const MAX_MESSAGE = 256 * 1024;
const MAX_FILE = 128 * 1024 * 1024;
const MAX_FIDS = 512;
const MAX_INODES = 16384;
const MAX_BUFFERED_BYTES = MAX_FILE * 2;
const NO_FID = 0xffffffff;
const UID = 1000;
const E = { NOENT: 2, IO: 5, BADF: 9, ACCES: 13, EXIST: 17, NOTDIR: 20,
  ISDIR: 21, INVAL: 22, MFILE: 24, FBIG: 27, NOSPC: 28, NOTEMPTY: 39,
  NOTSUP: 95, STALE: 116 };
const T = { STATFS: 8, OPEN: 12, CREATE: 14, GETATTR: 24, SETATTR: 26,
  READDIR: 40, FSYNC: 50, MKDIR: 72, RENAMEAT: 74, UNLINKAT: 76,
  VERSION: 100, ATTACH: 104, FLUSH: 108, WALK: 110, READ: 116, WRITE: 118, CLUNK: 120 };
const text = new TextEncoder();
const fromText = new TextDecoder('utf-8', { fatal: true });
const root = Object.freeze({ path: '/', directory: true, bytes: 0 });

function requireThat(condition, errno = E.INVAL) {
  if (!condition) throw Object.assign(new Error('Account filesystem request could not be completed.'), { errno });
}

class Packet {
  constructor(bytes, offset = 0) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.offset = offset;
  }
  take(count) {
    requireThat(Number.isSafeInteger(count) && count >= 0 && this.offset + count <= this.bytes.length);
    const offset = this.offset;
    this.offset += count;
    return offset;
  }
  u8(value) {
    const index = this.take(1);
    if (value === undefined) return this.view.getUint8(index);
    this.view.setUint8(index, value);
  }
  u16(value) {
    const index = this.take(2);
    if (value === undefined) return this.view.getUint16(index, true);
    this.view.setUint16(index, value, true);
  }
  u32(value) {
    const index = this.take(4);
    if (value === undefined) return this.view.getUint32(index, true);
    this.view.setUint32(index, value, true);
  }
  u64(value) {
    const index = this.take(8);
    if (value === undefined) {
      const integer = this.view.getBigUint64(index, true);
      requireThat(integer <= BigInt(Number.MAX_SAFE_INTEGER));
      return Number(integer);
    }
    this.view.setBigUint64(index, BigInt(value), true);
  }
  raw(bytes) { this.bytes.set(bytes, this.take(bytes.length)); }
  string(value) {
    if (value === undefined) {
      const count = this.u16();
      const start = this.take(count);
      try { return fromText.decode(this.bytes.subarray(start, start + count)); }
      catch { requireThat(false); }
    }
    const bytes = text.encode(value);
    this.u16(bytes.length);
    this.raw(bytes);
  }
}

function reply(type, tag, size, encode = () => {}) {
  const body = new Packet(new Uint8Array(size + HEADER), HEADER);
  encode(body);
  const frame = body.bytes.subarray(0, body.offset);
  const header = new Packet(frame);
  header.u32(frame.length);
  header.u8(type);
  header.u16(tag);
  return frame;
}

function child(parent, name) {
  requireThat(parent.directory, E.NOTDIR);
  requireThat(name && !name.includes('/') && !name.startsWith('.') &&
    !/[\\%?#\x00-\x1f\x7f]/.test(name) && text.encode(name).length <= 255,
  name.startsWith('.') ? E.NOENT : E.INVAL);
  return (parent.path === '/' ? '' : parent.path) + '/' + name;
}

function errno(error) {
  if (Number.isInteger(error?.errno)) return error.errno;
  switch (error?.status) {
    case 401: case 403: return E.ACCES;
    case 404: return E.NOENT;
    case 409: case 412: return E.STALE;
    case 413: return E.FBIG;
    case 507: return E.NOSPC;
    default: return E.IO;
  }
}

export function createAccountHome9p(home) {
  const fids = new Map();
  const inodes = new Map([['/', 1]]);
  let msize = MAX_MESSAGE;
  let nextInode = 1;
  let retainedBytes = 0;
  let tail = Promise.resolve();
  let closed = false;

  function qid(frame, entry) {
    if (!inodes.has(entry.path)) {
      requireThat(inodes.size < MAX_INODES, E.NOSPC);
      inodes.set(entry.path, ++nextInode);
    }
    frame.u8(entry.directory ? 128 : 0);
    frame.u32(0); // The kernel must revalidate, even if the pathname is unchanged.
    frame.u64(inodes.get(entry.path));
  }

  function fid(number) {
    const result = fids.get(number);
    requireThat(result, E.BADF);
    return result;
  }

  function newFid(number, entry) {
    requireThat(number !== NO_FID && !fids.has(number), E.BADF);
    requireThat(fids.size < MAX_FIDS, E.MFILE);
    fids.set(number, { entry });
  }

  async function listing(directory) {
    const result = await home.list(directory.path);
    requireThat(Array.isArray(result.entries), E.IO);
    return result.entries.map(entry => ({ ...entry, path: child(directory, entry.name) }));
  }

  async function lookup(path) {
    if (path === '/') return root;
    const split = path.lastIndexOf('/');
    const children = await listing({ path: path.slice(0, split) || '/', directory: true });
    const entry = children.find(item => item.path === path);
    requireThat(entry, E.NOENT);
    return entry;
  }

  function bytes(buffer, size) {
    requireThat(size <= MAX_FILE, E.FBIG);
    requireThat(retainedBytes - (buffer.data?.length ?? 0) + size <= MAX_BUFFERED_BYTES, E.NOSPC);
    if (buffer.data?.length === size) return;
    const data = new Uint8Array(size);
    if (buffer.data) data.set(buffer.data.subarray(0, size));
    retainedBytes += size - (buffer.data?.length ?? 0);
    buffer.data = data;
  }

  async function buffer(handle, { truncate = false } = {}) {
    requireThat(!handle.entry.directory, E.ISDIR);
    if (handle.snapshot) return handle.snapshot;
    const { entry } = handle;
    requireThat(entry.bytes <= MAX_FILE, E.FBIG);
    requireThat(retainedBytes + entry.bytes <= MAX_BUFFERED_BYTES, E.NOSPC);
    if (truncate) {
      const { sha256 } = await home.version(entry.path);
      return handle.snapshot = { data: new Uint8Array(), sha256, dirty: true };
    }
    const { data, sha256 } = await home.read(entry.path);
    requireThat(data instanceof Uint8Array && data.length <= MAX_FILE, E.IO);
    requireThat(retainedBytes + data.length <= MAX_BUFFERED_BYTES, E.NOSPC);
    retainedBytes += data.length;
    return handle.snapshot = { data, sha256, dirty: false };
  }

  async function commit(handle) {
    const state = handle.snapshot;
    if (!state?.dirty) return;
    const result = await home.write(handle.entry.path, state.data, state.sha256);
    requireThat(typeof result?.sha256 === 'string' && /^[0-9a-f]{64}$/.test(result.sha256), E.IO);
    state.sha256 = result.sha256;
    state.dirty = false;
    handle.entry = { ...handle.entry, bytes: state.data.length };
  }

  async function dispatch(type, tag, input) {
    const ok = (size = 0, encode) => reply(type + 1, tag, size, encode);
    if (type === T.VERSION) {
      const requested = input.u32();
      const version = input.string();
      requireThat(requested >= 4096);
      msize = Math.min(requested, MAX_MESSAGE);
      return ok(16, out => { out.u32(msize); out.string(version === '9P2000.L' ? version : 'unknown'); });
    }
    if (type === T.ATTACH) {
      const target = input.u32();
      requireThat(input.u32() === NO_FID, E.ACCES);
      input.string(); // User identity comes from the captured browser session.
      requireThat(input.string() === '', E.ACCES);
      newFid(target, root);
      return ok(13, out => qid(out, root));
    }
    if (type === T.FLUSH) return ok();
    const number = input.u32();
    const handle = fid(number);
    let entry = handle.entry;
    switch (type) {
      case T.WALK: {
        const next = input.u32();
        const count = input.u16();
        requireThat(count <= 16 && (next === number || !fids.has(next)));
        const entries = [];
        for (let i = 0; i < count; i++) {
          const name = input.string();
          try {
            const path = name === '.' ? entry.path : name === '..' ?
              entry.path.slice(0, entry.path.lastIndexOf('/')) || '/' : child(entry, name);
            entry = await lookup(path);
            entries.push(entry);
          } catch (error) {
            if (!entries.length || errno(error) !== E.NOENT) throw error;
            break;
          }
        }
        if (entries.length === count) {
          if (next === number) {
            requireThat(!handle.snapshot, E.BADF);
            handle.entry = entry;
          } else newFid(next, entry);
        }
        return ok(2 + 13 * entries.length, out => {
          out.u16(entries.length);
          for (const row of entries) qid(out, row);
        });
      }
      case T.STATFS:
        return ok(60, out => {
          out.u32(0x01021997); out.u32(4096);
          for (let i = 0; i < 6; i++) out.u64(0);
          out.u32(255);
        });
      case T.GETATTR: {
        const latest = handle.snapshot ? entry : await lookup(entry.path);
        const size = handle.snapshot?.data.length ?? latest.bytes ?? 0;
        return ok(153, out => {
          out.u64(0x61f); // Essential attributes. Server listings carry no timestamps.
          qid(out, latest);
          out.u32(latest.directory ? 0o40700 : 0o100600);
          out.u32(UID); out.u32(UID);
          out.u64(latest.directory ? 2 : 1); out.u64(0);
          out.u64(size); out.u64(4096); out.u64(Math.ceil(size / 512));
          for (let i = 0; i < 10; i++) out.u64(0);
        });
      }
      case T.OPEN: {
        const flags = input.u32();
        if (entry.directory) requireThat((flags & 3) === 0, E.ISDIR);
        handle.flags = flags;
        if (!entry.directory && flags & 0x200) {
          await buffer(handle, { truncate: true });
          await commit(handle);
          entry = handle.entry;
        }
        return ok(17, out => { qid(out, entry); out.u32(msize - 24); });
      }
      case T.READDIR: {
        requireThat(entry.directory, E.NOTDIR);
        let offset = input.u64();
        const count = Math.min(msize - 11, input.u32());
        if (!offset || !handle.dirEntries) handle.dirEntries = await listing(entry);
        return ok(4 + count, out => {
          const start = out.take(4);
          for (const row of handle.dirEntries.slice(offset)) {
            if (out.offset + 24 + text.encode(row.name).length > out.bytes.length) break;
            qid(out, row); out.u64(++offset);
            out.u8(row.directory ? 4 : 8); out.string(row.name);
          }
          out.view.setUint32(start, out.offset - start - 4, true);
        });
      }
      case T.READ: {
        requireThat(handle.flags !== undefined && (handle.flags & 3) !== 1, E.BADF);
        const offset = input.u64();
        const count = Math.min(msize - 11, input.u32());
        const state = await buffer(handle);
        const data = state.data.subarray(offset, offset + count);
        return ok(4 + data.length, out => { out.u32(data.length); out.raw(data); });
      }
      case T.CREATE: {
        const path = child(entry, input.string());
        const flags = input.u32();
        requireThat(!handle.snapshot, E.BADF);
        const data = new Uint8Array();
        const created = await home.write(path, data, null);
        requireThat(typeof created?.sha256 === 'string', E.IO);
        const result = { path, directory: false, bytes: 0 };
        handle.entry = result;
        handle.flags = flags;
        handle.snapshot = { data, sha256: created.sha256, dirty: false };
        return ok(17, out => { qid(out, result); out.u32(msize - 24); });
      }
      case T.SETATTR: {
        const valid = input.u32();
        const mode = input.u32();
        const uid = input.u32();
        const gid = input.u32();
        const size = input.u64();
        requireThat(!(valid & 2) || uid === UID, E.ACCES);
        requireThat(!(valid & 4) || gid === UID, E.ACCES);
        requireThat(!(valid & 1) || !(mode & 0o7000), E.ACCES);
        if (valid & 8) {
          const state = await buffer(handle, { truncate: size === 0 });
          bytes(state, size);
          state.dirty = true;
          if (handle.flags === undefined) await commit(handle);
        }
        return ok();
      }
      case T.WRITE: {
        requireThat(handle.flags !== undefined && (handle.flags & 3) !== 0, E.BADF);
        const offset = input.u64();
        const count = input.u32();
        const start = input.take(count);
        requireThat(offset <= MAX_FILE && offset + count <= MAX_FILE, E.FBIG);
        const state = await buffer(handle);
        if (offset + count > state.data.length) bytes(state, offset + count);
        state.data.set(input.bytes.subarray(start, start + count), offset);
        state.dirty ||= count !== 0;
        return ok(4, out => out.u32(count));
      }
      case T.MKDIR: {
        const path = child(entry, input.string());
        await home.mkdir(path);
        return ok(13, out => qid(out, { path, directory: true }));
      }
      case T.RENAMEAT: {
        const path = child(entry, input.string());
        const to = child(fid(input.u32()).entry, input.string());
        if (path === to) return ok();
        const source = await lookup(path);
        requireThat(!source.directory, E.NOTSUP); // Storage has no public folder rename route.
        for (const open of fids.values()) {
          requireThat(open.entry.path !== path || !open.snapshot?.dirty, E.STALE);
        }
        const { sha256 } = await home.version(path);
        await home.rename(path, to, sha256);
        if (inodes.has(path)) {
          inodes.set(to, inodes.get(path));
          inodes.delete(path);
        }
        for (const open of fids.values()) {
          if (open.entry.path === path) open.entry = { ...open.entry, path: to };
        }
        return ok();
      }
      case T.UNLINKAT: {
        const path = child(entry, input.string());
        const flags = input.u32();
        const target = await lookup(path);
        if (flags & 512) {
          requireThat(target.directory, E.NOTDIR);
          await home.rmdir(path);
        } else {
          requireThat(!target.directory, E.ISDIR);
          const { sha256 } = await home.version(path);
          await home.remove(path, sha256);
        }
        inodes.delete(path);
        return ok();
      }
      case T.FSYNC:
        await commit(handle);
        return ok();
      case T.CLUNK:
        await commit(handle);
        retainedBytes -= handle.snapshot?.data.length ?? 0;
        fids.delete(number);
        return ok();
      default:
        requireThat(false, E.NOTSUP);
    }
  }

  function request(frame) {
    const next = tail.then(async () => {
      const input = new Packet(frame);
      const size = input.u32();
      const type = input.u8();
      const tag = input.u16();
      try {
        requireThat(!closed && size === frame.length && size <= msize);
        return await dispatch(type, tag, input);
      } catch (error) {
        return reply(7, tag, 4, out => out.u32(errno(error)));
      }
    });
    tail = next.catch(() => {});
    return next;
  }

  return {
    request,
    close() {
      closed = true;
      home.close();
      // The active request may still be settling. It cannot serve a new account.
      void tail.then(() => fids.clear());
    },
  };
}
