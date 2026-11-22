const ETHERNET_MAX = 1518;
const QUEUE_MAX = 64;
const BUFFER_MAX = 65536;
const now = () => Math.floor(Date.now() / 1000);

/** Attach a single same-origin, signed wire to a VM. Account credentials stay in Accounts. */
export function connectGuestNetwork(emulator, authority, {signal, onStatus = () => {}} = {}) {
  if (!emulator?.bus || emulator.network_adapter || !authority) throw Error('An independent authorized guest is required.');
  const relay = new URL(authority.relayPath, location.href);
  if (relay.origin !== location.origin || relay.search || relay.hash || !relay.pathname.endsWith('/guest-network')) {
    throw Error('A same-origin guest relay is required.');
  }
  const cookie = new URL('./codi-guest-cookie', relay);
  relay.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const bus = emulator.bus, queue = [];
  let current, retryTimer, retryDelay = 1000, stopped = false, mac;

  function disconnect(wire, retry, message) {
    if (current !== wire) return;
    current = null;
    clearTimeout(wire.deadline);
    wire.abort.abort();
    wire.socket?.close();
    if (stopped) return;
    onStatus({mode: retry ? 'disconnected' : 'denied', message});
    if (retry) {
      retryTimer = setTimeout(open, retryDelay);
      retryDelay = Math.min(retryDelay * 2, 30000);
    }
  }
  function authorized(wire) {
    if (!wire?.lease || wire.lease <= now() || wire.socket?.readyState !== WebSocket.OPEN) return false;
    try { authority.check(); return true; }
    catch { disconnect(wire, false, 'Account changed.'); return false; }
  }
  function send(frame) {
    if (stopped || !current) return;
    // X11 produces Ethernet frames in its own same-origin iframe.
    const data = ArrayBuffer.isView(frame) ? new Uint8Array(frame.buffer, frame.byteOffset, frame.byteLength) :
      frame instanceof ArrayBuffer ? new Uint8Array(frame) : null;
    if (!data || data.byteLength < 14 || data.byteLength > ETHERNET_MAX) return;
    if (!(data[6] & 1) && !mac && data.subarray(6, 12).some(byte => byte)) mac = data.slice(6, 12);
    if (authorized(current)) {
      if (current.socket.bufferedAmount < BUFFER_MAX) current.socket.send(data);
      return;
    }
    if (!current) return;
    if (queue.length === QUEUE_MAX) queue.shift();
    queue.push(data.slice());
  }
  function announceLink(wire) {
    if (!mac) return;
    // A replacement relay does not know the guest MAC even if Linux kept its neighbor cache.
    for (const target of [1, 3]) {
      const arp = new Uint8Array(42);
      arp.fill(255, 0, 6);
      arp.set(mac, 6);
      arp.set([8, 6, 0, 1, 8, 0, 6, 4, 0, 1], 12);
      arp.set(mac, 22);
      arp.set([10, 86, 0, 2], 28);
      arp.set([10, 86, 0, target], 38);
      send(arp);
    }
  }
  async function receive(wire, data) {
    if (current !== wire) return;
    if (data instanceof ArrayBuffer) {
      if (authorized(wire) && data.byteLength >= 14 && data.byteLength <= ETHERNET_MAX) {
        bus.send('net0-receive', new Uint8Array(data));
      }
      return;
    }
    if (typeof data !== 'string' || data.length > 16384) throw Error('Invalid guest relay message.');
    const value = JSON.parse(data);
    if (value?.policy_sha256 !== authority.policyHash) throw Error('Guest network policy changed.');
    if (value.type === 'codi-guest-network-challenge/1') {
      if (wire.authorizing || wire.pending || wire.connection && wire.connection !== value.connection_id) {
        throw Error('Unexpected guest wire challenge.');
      }
      wire.authorizing = true;
      const {grant, proof, expiresAt} = await authority.connect(value, {signal: wire.abort.signal});
      if (current !== wire) return;
      wire.authorizing = false;
      wire.connection = value.connection_id;
      wire.pending = expiresAt;
      wire.socket.send(JSON.stringify({type: 'codi-guest-network-auth/1', grant, proof}));
    } else if (value.type === 'codi-guest-network-ready/1') {
      const lease = value.expires_at;
      if (value.kind !== 'registered' || value.connection_id !== wire.connection ||
          !Number.isSafeInteger(lease) || !wire.pending || lease <= now() || lease > wire.pending) {
        throw Error('Invalid guest wire acknowledgement.');
      }
      const first = !wire.lease;
      wire.lease = lease;
      wire.pending = null;
      retryDelay = 1000;
      clearTimeout(wire.deadline);
      wire.deadline = setTimeout(() => disconnect(wire, true, 'Guest lease ended.'), lease * 1000 - Date.now());
      if (first) {
        onStatus({mode: 'registered'});
        announceLink(wire);
        for (const frame of queue.splice(0)) send(frame);
      }
    } else if (value.type === 'codi-guest-network-state/1' && value.kind === 'anonymous') {
      disconnect(wire, true, 'Guest wire was retired.');
    } else {
      throw Error('Unexpected guest relay message.');
    }
  }
  async function open() {
    if (stopped || current) return;
    const wire = {abort: new AbortController()};
    current = wire;
    wire.deadline = setTimeout(() => disconnect(wire, true, 'Guest connection timed out.'), 15000);
    try {
      if (!await authority.status({signal: wire.abort.signal})) {
        disconnect(wire, false, 'Guest networking is unavailable to this account.');
        return;
      }
      if (!authority.statusSetsRelayCookie) {
        const response = await fetch(cookie, {credentials: 'same-origin', mode: 'same-origin', cache: 'no-store',
          redirect: 'error', signal: wire.abort.signal});
        await response.body?.cancel();
        if (!response.ok) throw Error('Guest connection could not be initialized.');
      }
      if (current !== wire) return;
      const socket = wire.socket = new WebSocket(relay);
      socket.binaryType = 'arraybuffer';
      socket.onopen = () => {
        if (current === wire) socket.send(JSON.stringify({type: 'codi-guest-network-begin/1'}));
      };
      socket.onmessage = event => void receive(wire, event.data).catch(error => {
        disconnect(wire, error.status !== 403, error.message);
      });
      socket.onclose = () => disconnect(wire, true, 'Guest network disconnected.');
    } catch (error) {
      disconnect(wire, error.name !== 'AbortError' && error.status !== 401 && error.status !== 403, error.message);
    }
  }
  function destroy() {
    if (stopped) return;
    stopped = true;
    signal?.removeEventListener('abort', destroy);
    clearTimeout(retryTimer);
    if (current) disconnect(current, false);
    queue.length = 0;
    bus.unregister?.('net0-send', send);
  }
  signal?.throwIfAborted();
  const connection = Object.freeze({destroy});
  emulator.network_adapter = connection;
  bus.register('net0-send', send, connection);
  signal?.addEventListener('abort', destroy, {once: true});
  void open();
  return connection;
}
