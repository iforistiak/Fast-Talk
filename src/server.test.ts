import test from 'node:test';
import assert from 'node:assert/strict';
import { WebSocket } from 'ws';
import {
  isSafeJsonObject,
  validateUsername,
  sanitizeFileName,
  escapeHtml,
  generateGuestUsername,
  SlidingWindowLimiter,
  createFastTalkServer
} from '../server.js';

test('isSafeJsonObject rejects arrays, primitives, and prototype pollution keys', () => {
  assert.equal(isSafeJsonObject(null), false);
  assert.equal(isSafeJsonObject([]), false);
  assert.equal(isSafeJsonObject('str'), false);
  assert.equal(isSafeJsonObject(JSON.parse('{"__proto__": {"polluted": true}}')), false);
  assert.equal(isSafeJsonObject({ type: 'register', username: 'alice' }), true);
});

test('validateUsername enforces 3-20 alphanumeric and underscore rules', () => {
  assert.equal(validateUsername('ab').valid, false);
  assert.equal(validateUsername('a'.repeat(21)).valid, false);
  assert.equal(validateUsername('bad-name').valid, false);
  assert.equal(validateUsername('bad space').valid, false);
  assert.equal(validateUsername('<script>').valid, false);

  const validRes = validateUsername('  alice_01  ');
  assert.equal(validRes.valid, true);
  assert.equal(validRes.username, 'alice_01');
});

test('sanitizeFileName strips path traversal and unsafe characters', () => {
  assert.equal(sanitizeFileName('../../etc/passwd'), 'passwd');
  assert.equal(sanitizeFileName('C:\\Users\\admin\\report<1>.pdf'), 'report_1_.pdf');
  assert.equal(sanitizeFileName('   '), 'shared_file');
});

test('escapeHtml escapes XSS vectors', () => {
  assert.equal(
    escapeHtml('<img src=x onerror="alert(\'xss\')">&'),
    '&lt;img src=x onerror=&quot;alert(&#39;xss&#39;)&quot;&gt;&amp;'
  );
});

test('generateGuestUsername creates unique Guest_1234 names', () => {
  const map = new Map();
  const guest = generateGuestUsername(map);
  assert.match(guest, /^Guest_\d{4}$/);
});

test('SlidingWindowLimiter blocks excess events within window', () => {
  const limiter = new SlidingWindowLimiter(3, 1000);
  assert.equal(limiter.allow(100), true);
  assert.equal(limiter.allow(200), true);
  assert.equal(limiter.allow(300), true);
  assert.equal(limiter.allow(400), false);
  assert.equal(limiter.allow(1101), true);
});

test('Full in-memory WebSocket signaling, search, chat, file relay, and wipe flow', async () => {
  const app = createFastTalkServer({ heartbeatIntervalMs: 60000 });
  await new Promise<void>((resolve) => app.httpServer.listen(0, '127.0.0.1', () => resolve()));
  const address = app.httpServer.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  const wsUrl = `ws://127.0.0.1:${port}`;

  function createClient() {
    const ws = new WebSocket(wsUrl);
    const queue: any[] = [];
    const waiters: Array<(msg: any) => boolean> = [];

    ws.on('message', (data) => {
      const parsed = JSON.parse(data.toString('utf8'));
      for (let i = 0; i < waiters.length; i++) {
        if (waiters[i](parsed)) {
          waiters.splice(i, 1);
          return;
        }
      }
      queue.push(parsed);
    });

    function waitForType(type: string, timeoutMs = 3000): Promise<any> {
      const idx = queue.findIndex((m) => m.type === type);
      if (idx !== -1) {
        return Promise.resolve(queue.splice(idx, 1)[0]);
      }
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`Timeout waiting for ${type}`)), timeoutMs);
        waiters.push((msg) => {
          if (msg.type === type) {
            clearTimeout(timer);
            resolve(msg);
            return true;
          }
          return false;
        });
      });
    }

    return {
      ws,
      send: (obj: any) => ws.send(JSON.stringify(obj)),
      waitForType,
      open: () =>
        new Promise<void>((resolve) => {
          if (ws.readyState === WebSocket.OPEN) resolve();
          else ws.once('open', () => resolve());
        })
    };
  }

  const alice = createClient();
  const bob = createClient();
  const dup = createClient();

  try {
    await Promise.all([alice.open(), bob.open(), dup.open()]);

    // 1. Register Alice
    alice.send({ type: 'register', isGuest: false, username: 'Alice_Corp' });
    const aliceReg = await alice.waitForType('registered');
    assert.equal(aliceReg.username, 'Alice_Corp');

    // 2. Reject duplicate Alice (case-insensitive)
    dup.send({ type: 'register', isGuest: false, username: 'alice_corp' });
    const dupErr = await dup.waitForType('register_error');
    assert.match(dupErr.message, /already online/i);

    // 3. Register Bob as Guest
    bob.send({ type: 'register', isGuest: true });
    const bobReg = await bob.waitForType('registered');
    assert.match(bobReg.username, /^Guest_\d{4}$/);

    // 4. Partial-match search from Alice for "Guest_"
    alice.send({ type: 'search_users', query: 'guest_' });
    const searchRes = await alice.waitForType('search_results');
    assert.equal(searchRes.users.length, 1);
    assert.equal(searchRes.users[0].username, bobReg.username);

    // 5. Chat Request -> Accept flow
    alice.send({ type: 'chat_request', to: bobReg.username });
    const incomingReq = await bob.waitForType('chat_request');
    assert.equal(incomingReq.from, 'Alice_Corp');

    bob.send({ type: 'chat_accept', from: 'Alice_Corp' });
    const [aliceAccepted, bobAccepted] = await Promise.all([
      alice.waitForType('chat_accepted'),
      bob.waitForType('chat_accepted')
    ]);
    assert.equal(aliceAccepted.partner, bobReg.username);
    assert.equal(aliceAccepted.initiator, true);
    assert.equal(bobAccepted.partner, 'Alice_Corp');
    assert.equal(bobAccepted.initiator, false);

    // 6. Real-time text message & typing indicator
    alice.send({ type: 'typing', to: bobReg.username, isTyping: true });
    const typingEvt = await bob.waitForType('typing');
    assert.equal(typingEvt.from, 'Alice_Corp');
    assert.equal(typingEvt.isTyping, true);

    alice.send({
      type: 'chat_message',
      id: 'msg_1',
      to: bobReg.username,
      text: 'Hello Bob <script>alert(1)</script>'
    });
    const chatMsg = await bob.waitForType('chat_message');
    assert.equal(chatMsg.from, 'Alice_Corp');
    assert.equal(chatMsg.text, 'Hello Bob <script>alert(1)</script>');

    // 6b. Read receipt relay when partner views/clicks active chat
    bob.send({ type: 'read_receipt', to: 'Alice_Corp' });
    const readEvt = await alice.waitForType('read_receipt');
    assert.equal(readEvt.from, bobReg.username);

    // 7. Chunked file relay fallback (file_meta -> file_chunk -> file_ack -> file_complete)
    alice.send({
      type: 'file_meta',
      to: bobReg.username,
      fileId: 'file_101',
      name: '../secret_spec.txt',
      size: 11,
      mimeType: 'text/plain'
    });
    const fileMeta = await bob.waitForType('file_meta');
    assert.equal(fileMeta.name, 'secret_spec.txt');
    assert.equal(fileMeta.totalChunks, 1);

    const chunkBase64 = Buffer.from('hello world', 'utf8').toString('base64');
    alice.send({
      type: 'file_chunk',
      to: bobReg.username,
      fileId: 'file_101',
      chunkIndex: 0,
      data: chunkBase64
    });
    const fileChunk = await bob.waitForType('file_chunk');
    assert.equal(fileChunk.chunkIndex, 0);
    assert.equal(Buffer.from(fileChunk.data, 'base64').toString('utf8'), 'hello world');

    bob.send({
      type: 'file_ack',
      to: 'Alice_Corp',
      fileId: 'file_101',
      chunkIndex: 0
    });
    const fileAck = await alice.waitForType('file_ack');
    assert.equal(fileAck.chunkIndex, 0);

    alice.send({
      type: 'file_complete',
      to: bobReg.username,
      fileId: 'file_101'
    });
    const fileComplete = await bob.waitForType('file_complete');
    assert.equal(fileComplete.fileId, 'file_101');

    // 8. End chat & wipe notifies both users and clears pairing
    bob.send({ type: 'end_chat', to: 'Alice_Corp' });
    const [aliceWiped, bobWiped] = await Promise.all([
      alice.waitForType('chat_wiped'),
      bob.waitForType('chat_wiped')
    ]);
    assert.equal(aliceWiped.partner, bobReg.username);
    assert.equal(bobWiped.partner, 'Alice_Corp');
  } finally {
    alice.ws.close();
    bob.ws.close();
    dup.ws.close();
    await app.close();
  }
});
