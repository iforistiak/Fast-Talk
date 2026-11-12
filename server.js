/**
 * Fast Talk — Ephemeral Real-Time Signaling & Relay Server
 * Ideas Deployed By - MD. ISTIAK ISLAM
 * Licensed under the MIT License
 */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { WebSocketServer, WebSocket } from 'ws';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================
const DEFAULT_PORT =
  process.env.PORT && process.env.PORT !== '8080'
    ? Number(process.env.PORT)
    : 3000;
const MAX_WS_PAYLOAD_BYTES = 64 * 1024;        // 64 KB max single WS frame
const MAX_HTTP_BODY_BYTES = 128 * 1024;        // 128 KB max HTTP batch body
const MAX_TEXT_LENGTH = 4000;                  // Max characters in a chat message
const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100 MB max file size
const CHUNK_SIZE_BYTES = 16 * 1024;            // 16 KB standard chunk size
const HEARTBEAT_INTERVAL_MS = 15000;           // 15s ping/pong & stale session check
const HTTP_SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30m session retention for mobile background tabs

// ============================================================================
// PURE VALIDATION & SANITIZATION HELPERS
// ============================================================================

/**
 * Guards against prototype pollution keys in parsed JSON objects.
 */
export function isSafeJsonObject(val) {
  if (!val || typeof val !== 'object' || Array.isArray(val)) return false;
  if (
    Object.prototype.hasOwnProperty.call(val, '__proto__') ||
    Object.prototype.hasOwnProperty.call(val, 'constructor') ||
    Object.prototype.hasOwnProperty.call(val, 'prototype')
  ) {
    return false;
  }
  return true;
}

/**
 * Validates a custom username: 3-20 characters, alphanumeric + underscore only.
 */
export function validateUsername(raw) {
  if (typeof raw !== 'string') {
    return { valid: false, error: 'Username must be a string.' };
  }
  const trimmed = raw.trim();
  if (trimmed.length < 3 || trimmed.length > 20) {
    return {
      valid: false,
      error: 'Username must be between 3 and 20 characters long.'
    };
  }
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(trimmed)) {
    return {
      valid: false,
      error: 'Username may only contain letters, numbers, and underscores (_).'
    };
  }
  return { valid: true, username: trimmed };
}

/**
 * Sanitizes a file name to prevent path traversal or control-character injection.
 */
export function sanitizeFileName(name) {
  if (typeof name !== 'string' || !name.trim()) {
    return 'shared_file';
  }
  const base = name
    .replace(/\\/g, '/')
    .split('/')
    .pop()
    .replace(/[\x00-\x1F\x7F<>:"|?*]/g, '_')
    .trim();
  if (!base || base === '.' || base === '..') {
    return 'shared_file';
  }
  return base.slice(0, 180);
}

/**
 * Escapes HTML special characters to prevent XSS.
 */
export function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Generates a unique Guest_1234 username not present in the given active Map.
 */
export function generateGuestUsername(usersByLower) {
  for (let attempt = 0; attempt < 500; attempt++) {
    const num = crypto.randomInt(1000, 10000);
    const candidate = `Guest_${num}`;
    if (!usersByLower.has(candidate.toLowerCase())) {
      return candidate;
    }
  }
  const fallbackNum = crypto.randomInt(100000, 1000000);
  return `Guest_${fallbackNum}`;
}

/**
 * Sliding-window rate limiter kept strictly in memory per connection.
 */
export class SlidingWindowLimiter {
  constructor(maxEvents, windowMs) {
    this.maxEvents = maxEvents;
    this.windowMs = windowMs;
    this.timestamps = [];
  }

  allow(now = Date.now()) {
    const cutoff = now - this.windowMs;
    while (this.timestamps.length > 0 && this.timestamps[0] <= cutoff) {
      this.timestamps.shift();
    }
    if (this.timestamps.length >= this.maxEvents) {
      return false;
    }
    this.timestamps.push(now);
    return true;
  }
}

// ============================================================================
// IN-MEMORY EPHEMERAL SERVER FACTORY (WEBSOCKET + HTTP FALLBACK TRANSPORT)
// ============================================================================

export function createFastTalkServer(options = {}) {
  const indexHtmlPath = options.indexHtmlPath || path.join(__dirname, 'index.html');
  const heartbeatIntervalMs = options.heartbeatIntervalMs || HEARTBEAT_INTERVAL_MS;

  /**
   * Primary in-memory state:
   * usersByLower: Map<lowerUsername, UserSession>
   * connectionsById: Map<connId, VirtualConnection>
   */
  const usersByLower = new Map();
  const connectionsById = new Map();
  let eventIdSeq = 0;

  function createVirtualConnection(connId, ws = null) {
    const id = connId || crypto.randomUUID();
    let conn = connectionsById.get(id);
    if (!conn) {
      conn = {
        id,
        ws: ws || null,
        hasHttp: !ws,
        userLower: null,
        lastSeen: Date.now(),
        outbox: [],
        preAuthLimiter: new SlidingWindowLimiter(50, 10000)
      };
      connectionsById.set(id, conn);
    } else {
      if (ws) {
        conn.ws = ws;
      } else {
        conn.hasHttp = true;
      }
      conn.lastSeen = Date.now();
    }
    return conn;
  }

  function isConnectionActive(conn) {
    if (!conn) return false;
    if (conn.ws && conn.ws.readyState === WebSocket.OPEN) return true;
    return Date.now() - conn.lastSeen <= HTTP_SESSION_TIMEOUT_MS;
  }

  /**
   * Delivers a JSON event to a virtual connection (via live WebSocket if open,
   * AND queues in conn.outbox for HTTP polling reconciliation).
   */
  function sendToConn(conn, payload) {
    if (!conn) return;
    const stamped =
      payload && typeof payload === 'object' && !payload._eid
        ? { ...payload, _eid: ++eventIdSeq }
        : payload;

    let sentViaWs = false;
    if (conn.ws && conn.ws.readyState === WebSocket.OPEN) {
      try {
        conn.ws.send(JSON.stringify(stamped));
        sentViaWs = true;
      } catch {
        // Fall through to outbox queue if WS write fails
      }
    }
    if ((!sentViaWs || conn.hasHttp) && conn.outbox.length < 2500) {
      conn.outbox.push(stamped);
    }
  }

  function normalizeTargetHandle(raw) {
    if (typeof raw !== 'string') return '';
    return raw.trim().replace(/^@+/, '').trim();
  }

  function resolveOnlineUserSession(rawInput, excludeLower = '') {
    const clean = normalizeTargetHandle(rawInput);
    if (!clean) return null;
    const cleanLower = clean.toLowerCase();

    const direct = usersByLower.get(cleanLower);
    if (direct && direct.lower !== excludeLower && isConnectionActive(direct.conn)) {
      return direct;
    }

    // Support 4-digit Guest ID shorthand (e.g. "4821" -> "Guest_4821")
    if (/^\d{4}$/.test(cleanLower)) {
      const guestSession = usersByLower.get(`guest_${cleanLower}`);
      if (guestSession && guestSession.lower !== excludeLower && isConnectionActive(guestSession.conn)) {
        return guestSession;
      }
    }

    // Support normalized match without underscores/spaces (e.g. "guest4821" -> "Guest_4821")
    const normInput = cleanLower.replace(/[\s_-]+/g, '');
    if (normInput.length >= 3) {
      for (const [lower, session] of usersByLower.entries()) {
        if (lower === excludeLower) continue;
        if (!isConnectionActive(session.conn)) continue;
        if (lower.replace(/_/g, '') === normInput) {
          return session;
        }
      }
    }

    return null;
  }

  function searchOnlineUsers(excludeLower, query = '') {
    const cleanQuery = normalizeTargetHandle(query).toLowerCase();
    const normQuery = cleanQuery.replace(/[\s_-]+/g, '');
    const scored = [];

    for (const [lower, session] of usersByLower.entries()) {
      if (lower === excludeLower) continue;
      if (!isConnectionActive(session.conn)) continue;

      if (!cleanQuery) {
        scored.push({
          score: 10,
          username: session.username,
          joinedAt: session.joinedAt
        });
        continue;
      }

      const normLower = lower.replace(/_/g, '');
      let score = -1;

      if (lower === cleanQuery || (normQuery && normLower === normQuery)) {
        score = 0; // Exact match
      } else if (/^\d{4}$/.test(cleanQuery) && lower === `guest_${cleanQuery}`) {
        score = 0; // Exact 4-digit Guest ID match
      } else if (lower.startsWith(cleanQuery) || (normQuery && normLower.startsWith(normQuery))) {
        score = 1; // Prefix match
      } else if (lower.includes(cleanQuery) || (normQuery && normLower.includes(normQuery))) {
        score = 2; // Substring / normalized match
      }

      if (score !== -1) {
        scored.push({
          score,
          username: session.username,
          joinedAt: session.joinedAt
        });
      }
    }

    scored.sort((a, b) => a.score - b.score || a.username.localeCompare(b.username));
    return scored.map(({ username, joinedAt }) => ({ username, joinedAt }));
  }

  function broadcastDirectoryUpdate() {
    for (const [lower, session] of usersByLower.entries()) {
      sendToConn(session.conn, {
        type: 'online_users',
        users: searchOnlineUsers(lower, ''),
        totalOnline: usersByLower.size
      });
    }
  }

  function syncDeferredRequestsForSession(session) {
    if (!session) return;
    const myLower = session.lower;
    const now = Date.now();

    for (const [otherLower, otherSession] of usersByLower.entries()) {
      if (otherLower === myLower) continue;

      if (otherSession.outgoingRequests.has(myLower)) {
        // If both users already requested each other, auto-pair them into an active chat!
        if (session.outgoingRequests.has(otherLower)) {
          otherSession.outgoingRequests.delete(myLower);
          session.outgoingRequests.delete(otherLower);
          otherSession.incomingRequests.delete(myLower);
          session.incomingRequests.delete(otherLower);

          otherSession.activePartners.add(myLower);
          session.activePartners.add(otherLower);

          sendToConn(otherSession.conn, {
            type: 'chat_accepted',
            partner: session.username,
            initiator: true,
            timestamp: now
          });
          sendToConn(session.conn, {
            type: 'chat_accepted',
            partner: otherSession.username,
            initiator: false,
            timestamp: now
          });
        } else if (!session.activePartners.has(otherLower) && !session.incomingRequests.has(otherLower)) {
          session.incomingRequests.add(otherLower);
          sendToConn(session.conn, {
            type: 'chat_request',
            from: otherSession.username,
            timestamp: now
          });
        }
      }
    }
  }

  function ensureSessionBound(conn, rawUsername, rawClientToken) {
    if (!conn) return null;
    if (conn.userLower && usersByLower.has(conn.userLower)) {
      const active = usersByLower.get(conn.userLower);
      if (active) {
        active.conn = conn;
        conn.lastSeen = Date.now();
        syncDeferredRequestsForSession(active);
        return active;
      }
    }

    const check = validateUsername(normalizeTargetHandle(rawUsername));
    if (!check.valid) return null;

    const lower = check.username.toLowerCase();
    const clientToken =
      typeof rawClientToken === 'string' && rawClientToken.length >= 8 && rawClientToken.length <= 80
        ? rawClientToken
        : null;

    const existing = usersByLower.get(lower);
    if (existing) {
      if (!existing.clientToken || (clientToken && existing.clientToken === clientToken)) {
        if (existing.conn && existing.conn !== conn) {
          existing.conn.userLower = null;
          if (existing.conn.outbox.length > 0) {
            for (const queued of existing.conn.outbox.splice(0, existing.conn.outbox.length)) {
              sendToConn(conn, queued);
            }
          }
        }
        existing.conn = conn;
        existing.ws = conn.ws;
        if (clientToken) existing.clientToken = clientToken;
        conn.userLower = lower;
        conn.lastSeen = Date.now();
        syncDeferredRequestsForSession(existing);
        return existing;
      }
      return null;
    }

    // Automatically restore session if it was dropped by a socket blip
    const restored = {
      username: check.username,
      lower,
      clientToken,
      conn,
      ws: conn.ws,
      joinedAt: Date.now(),
      activePartners: new Set(),
      incomingRequests: new Set(),
      outgoingRequests: new Set(),
      controlLimiter: new SlidingWindowLimiter(120, 10000),
      chunkLimiter: new SlidingWindowLimiter(1400, 5000)
    };
    usersByLower.set(lower, restored);
    conn.userLower = lower;
    conn.lastSeen = Date.now();
    syncDeferredRequestsForSession(restored);
    broadcastDirectoryUpdate();
    return restored;
  }

  function cleanupUserSession(lower, reason = 'disconnected') {
    const session = usersByLower.get(lower);
    if (!session) return;

    usersByLower.delete(lower);
    if (session.conn && session.conn.userLower === lower) {
      session.conn.userLower = null;
    }

    for (const targetLower of session.outgoingRequests) {
      const target = usersByLower.get(targetLower);
      if (target) {
        target.incomingRequests.delete(lower);
        sendToConn(target.conn, {
          type: 'chat_request_cancelled',
          from: session.username,
          reason
        });
      }
    }

    for (const requesterLower of session.incomingRequests) {
      const requester = usersByLower.get(requesterLower);
      if (requester) {
        requester.outgoingRequests.delete(lower);
        sendToConn(requester.conn, {
          type: 'chat_declined',
          from: session.username,
          reason: 'User went offline.'
        });
      }
    }

    for (const partnerLower of session.activePartners) {
      const partner = usersByLower.get(partnerLower);
      if (partner) {
        partner.activePartners.delete(lower);
        sendToConn(partner.conn, {
          type: 'partner_disconnected',
          from: session.username,
          wipe: true,
          reason,
          timestamp: Date.now()
        });
      }
    }

    session.outgoingRequests.clear();
    session.incomingRequests.clear();
    session.activePartners.clear();

    broadcastDirectoryUpdate();
  }

  function wipeChatBetween(userALower, userBLower, initiatedByUsername, reason = 'Ended & wiped by partner') {
    const userA = usersByLower.get(userALower);
    const userB = usersByLower.get(userBLower);

    if (userA) {
      userA.activePartners.delete(userBLower);
      userA.incomingRequests.delete(userBLower);
      userA.outgoingRequests.delete(userBLower);
    }
    if (userB) {
      userB.activePartners.delete(userALower);
      userB.incomingRequests.delete(userALower);
      userB.outgoingRequests.delete(userALower);
    }

    const timestamp = Date.now();
    if (userA) {
      sendToConn(userA.conn, {
        type: 'chat_wiped',
        partner: userB ? userB.username : userBLower,
        initiatedBy: initiatedByUsername,
        reason,
        timestamp
      });
    }
    if (userB) {
      sendToConn(userB.conn, {
        type: 'chat_wiped',
        partner: userA ? userA.username : initiatedByUsername,
        initiatedBy: initiatedByUsername,
        reason,
        timestamp
      });
    }
  }

  /**
   * Unified protocol message processor for both WebSocket frames and HTTP fallback batches.
   */
  function processProtocolMessage(conn, msg) {
    conn.lastSeen = Date.now();

    if (!isSafeJsonObject(msg) || typeof msg.type !== 'string') {
      sendToConn(conn, {
        type: 'error',
        code: 'MISSING_TYPE',
        message: 'Valid message object and type are required.'
      });
      return;
    }

    if (msg.type === 'ping') {
      sendToConn(conn, { type: 'pong', timestamp: Date.now() });
      return;
    }

    // ------------------------------------------------------------------------
    // 1. REGISTRATION (Custom username or Guest_1234)
    // ------------------------------------------------------------------------
    if (msg.type === 'register') {
      if (!conn.preAuthLimiter.allow()) {
        sendToConn(conn, {
          type: 'register_error',
          message: 'Too many registration attempts. Please wait a moment.'
        });
        return;
      }

      let chosenUsername = '';
      if (msg.isGuest === true) {
        chosenUsername = generateGuestUsername(usersByLower);
      } else {
        const check = validateUsername(msg.username);
        if (!check.valid) {
          sendToConn(conn, {
            type: 'register_error',
            message: check.error
          });
          return;
        }
        chosenUsername = check.username;
      }

      const lower = chosenUsername.toLowerCase();
      const clientToken =
        typeof msg.clientToken === 'string' && msg.clientToken.length >= 8 && msg.clientToken.length <= 80
          ? msg.clientToken
          : null;

      // If this connection (or matching clientToken) is already registered with the same username, re-bind & sync
      const existing = usersByLower.get(lower);
      if (
        existing &&
        (existing.conn === conn || (clientToken && existing.clientToken === clientToken))
      ) {
        if (existing.conn && existing.conn !== conn) {
          existing.conn.userLower = null;
          if (existing.conn.outbox.length > 0) {
            for (const queued of existing.conn.outbox.splice(0, existing.conn.outbox.length)) {
              sendToConn(conn, queued);
            }
          }
        }
        existing.conn = conn;
        existing.ws = conn.ws;
        conn.userLower = lower;

        sendToConn(conn, {
          type: 'registered',
          username: existing.username,
          joinedAt: existing.joinedAt,
          users: searchOnlineUsers(lower, ''),
          totalOnline: usersByLower.size
        });
        syncDeferredRequestsForSession(existing);
        return;
      }

      // If this connection was registered as a different username, clean up previous
      if (conn.userLower && conn.userLower !== lower && usersByLower.has(conn.userLower)) {
        cleanupUserSession(conn.userLower, 're-registered');
      }

      if (existing) {
        const hasLiveWs = Boolean(
          existing.conn &&
            existing.conn.ws &&
            existing.conn.ws.readyState === WebSocket.OPEN
        );
        const hasRecentHttpPoll = Boolean(
          existing.conn && !existing.conn.ws && Date.now() - existing.conn.lastSeen <= 2500
        );
        if ((hasLiveWs || hasRecentHttpPoll) && existing.conn !== conn) {
          sendToConn(conn, {
            type: 'register_error',
            message: `Username "${chosenUsername}" is already online. Please pick another username.`
          });
          return;
        } else {
          cleanupUserSession(lower, 'stale_socket_replaced');
        }
      }

      const session = {
        username: chosenUsername,
        lower,
        clientToken,
        conn,
        ws: conn.ws,
        joinedAt: Date.now(),
        activePartners: new Set(),
        incomingRequests: new Set(),
        outgoingRequests: new Set(),
        controlLimiter: new SlidingWindowLimiter(120, 10000),
        chunkLimiter: new SlidingWindowLimiter(1400, 5000)
      };

      usersByLower.set(lower, session);
      conn.userLower = lower;

      sendToConn(conn, {
        type: 'registered',
        username: chosenUsername,
        joinedAt: session.joinedAt,
        users: searchOnlineUsers(lower, ''),
        totalOnline: usersByLower.size
      });

      syncDeferredRequestsForSession(session);
      broadcastDirectoryUpdate();
      return;
    }

    let currentSession = conn.userLower ? usersByLower.get(conn.userLower) : null;
    if (!currentSession && typeof msg._user === 'string') {
      currentSession = ensureSessionBound(conn, msg._user, msg._token);
    }

    // Allow search_users even if session is not yet bound
    if (msg.type === 'search_users' && !currentSession) {
      const query = typeof msg.query === 'string' ? msg.query.slice(0, 40) : '';
      const matches = searchOnlineUsers('', query);
      sendToConn(conn, {
        type: 'search_results',
        query,
        users: matches,
        totalOnline: usersByLower.size
      });
      return;
    }

    if (!currentSession) {
      sendToConn(conn, {
        type: 'error',
        code: 'UNAUTHORIZED',
        message: 'Please register a username before performing this action.'
      });
      return;
    }

    const isChunkTraffic =
      msg.type === 'file_chunk' ||
      msg.type === 'file_ack' ||
      msg.type === 'rtc_signal';

    if (isChunkTraffic) {
      if (!currentSession.chunkLimiter.allow()) {
        sendToConn(conn, {
          type: 'error',
          code: 'RATE_LIMIT',
          message: 'File relay rate limit reached. Pausing briefly.'
        });
        return;
      }
    } else {
      if (!currentSession.controlLimiter.allow()) {
        sendToConn(conn, {
          type: 'error',
          code: 'RATE_LIMIT',
          message: 'Rate limit exceeded. Please slow down.'
        });
        return;
      }
    }

    // ------------------------------------------------------------------------
    // 2. LOGOUT
    // ------------------------------------------------------------------------
    if (msg.type === 'logout') {
      const lower = currentSession.lower;
      conn.userLower = null;
      cleanupUserSession(lower, 'logged_out');
      sendToConn(conn, { type: 'logged_out' });
      return;
    }

    // ------------------------------------------------------------------------
    // 3. LIVE PARTIAL-MATCH USERNAME SEARCH
    // ------------------------------------------------------------------------
    if (msg.type === 'search_users') {
      const query = typeof msg.query === 'string' ? msg.query.slice(0, 40) : '';
      const matches = searchOnlineUsers(currentSession.lower, query);
      sendToConn(conn, {
        type: 'search_results',
        query,
        users: matches,
        allUsers: searchOnlineUsers(currentSession.lower, ''),
        totalOnline: usersByLower.size
      });
      return;
    }

    // ------------------------------------------------------------------------
    // 4. CHAT REQUEST / CANCEL / ACCEPT / DECLINE
    // ------------------------------------------------------------------------
    if (msg.type === 'chat_request') {
      const targetRaw = normalizeTargetHandle(msg.to);
      const targetSession = resolveOnlineUserSession(targetRaw, currentSession.lower);
      const targetLower = targetSession ? targetSession.lower : targetRaw.toLowerCase();

      if (!targetLower || targetLower === currentSession.lower) {
        sendToConn(conn, {
          type: 'error',
          code: 'INVALID_TARGET',
          message: 'Cannot send a chat request to yourself.'
        });
        return;
      }

      // If target is not online yet, queue the outgoing request so it auto-delivers when target comes online
      if (!targetSession) {
        const validCheck = validateUsername(targetRaw);
        if (!validCheck.valid) {
          sendToConn(conn, {
            type: 'error',
            code: 'INVALID_TARGET',
            message: validCheck.error
          });
          return;
        }
        currentSession.outgoingRequests.add(targetLower);
        sendToConn(currentSession.conn, {
          type: 'chat_request_sent',
          to: validCheck.username,
          deferred: true,
          timestamp: Date.now()
        });
        return;
      }

      if (currentSession.activePartners.has(targetLower)) {
        sendToConn(conn, {
          type: 'chat_accepted',
          partner: targetSession.username,
          initiator: true,
          timestamp: Date.now()
        });
        return;
      }

      // If target already requested us (or mutual Connect clicked on both sides), immediately pair & accept!
      if (
        currentSession.incomingRequests.has(targetLower) ||
        targetSession.outgoingRequests.has(currentSession.lower)
      ) {
        currentSession.incomingRequests.delete(targetLower);
        currentSession.outgoingRequests.delete(targetLower);
        targetSession.outgoingRequests.delete(currentSession.lower);
        targetSession.incomingRequests.delete(currentSession.lower);

        currentSession.activePartners.add(targetLower);
        targetSession.activePartners.add(currentSession.lower);

        const now = Date.now();
        sendToConn(targetSession.conn, {
          type: 'chat_accepted',
          partner: currentSession.username,
          initiator: true,
          timestamp: now
        });
        sendToConn(currentSession.conn, {
          type: 'chat_accepted',
          partner: targetSession.username,
          initiator: false,
          timestamp: now
        });
        return;
      }

      currentSession.outgoingRequests.add(targetLower);
      targetSession.incomingRequests.add(currentSession.lower);

      const timestamp = Date.now();
      sendToConn(currentSession.conn, {
        type: 'chat_request_sent',
        to: targetSession.username,
        timestamp
      });

      sendToConn(targetSession.conn, {
        type: 'chat_request',
        from: currentSession.username,
        timestamp
      });
      return;
    }

    if (msg.type === 'chat_request_cancel') {
      const targetLower = normalizeTargetHandle(msg.to).toLowerCase();
      const targetSession = usersByLower.get(targetLower);
      currentSession.outgoingRequests.delete(targetLower);
      if (targetSession) {
        targetSession.incomingRequests.delete(currentSession.lower);
        sendToConn(targetSession.conn, {
          type: 'chat_request_cancelled',
          from: currentSession.username
        });
      }
      return;
    }

    if (msg.type === 'chat_accept') {
      const requesterRaw = normalizeTargetHandle(msg.from);
      const requesterSession = resolveOnlineUserSession(requesterRaw, currentSession.lower);
      const requesterLower = requesterSession ? requesterSession.lower : requesterRaw.toLowerCase();

      if (!requesterSession) {
        currentSession.incomingRequests.delete(requesterLower);
        sendToConn(conn, {
          type: 'error',
          code: 'USER_OFFLINE',
          message: `User "${requesterRaw}" went offline before the request could be accepted.`
        });
        return;
      }

      currentSession.incomingRequests.delete(requesterLower);
      currentSession.outgoingRequests.delete(requesterLower);
      requesterSession.outgoingRequests.delete(currentSession.lower);
      requesterSession.incomingRequests.delete(currentSession.lower);

      currentSession.activePartners.add(requesterLower);
      requesterSession.activePartners.add(currentSession.lower);

      const timestamp = Date.now();
      sendToConn(requesterSession.conn, {
        type: 'chat_accepted',
        partner: currentSession.username,
        initiator: true,
        timestamp
      });
      sendToConn(currentSession.conn, {
        type: 'chat_accepted',
        partner: requesterSession.username,
        initiator: false,
        timestamp
      });
      return;
    }

    if (msg.type === 'chat_decline') {
      const requesterRaw = normalizeTargetHandle(msg.from);
      const requesterLower = requesterRaw.toLowerCase();
      const requesterSession = usersByLower.get(requesterLower);

      currentSession.incomingRequests.delete(requesterLower);
      if (requesterSession) {
        requesterSession.outgoingRequests.delete(currentSession.lower);
        sendToConn(requesterSession.conn, {
          type: 'chat_declined',
          from: currentSession.username,
          reason: 'Chat request was declined.',
          timestamp: Date.now()
        });
      }
      return;
    }

    // ------------------------------------------------------------------------
    // 5. ACTIVE PARTNER VERIFICATION FOR MESSAGING, WEBRTC & FILE RELAY
    // ------------------------------------------------------------------------
    const partnerRaw = normalizeTargetHandle(msg.to);
    const partnerLower = partnerRaw.toLowerCase();
    const partnerSession = usersByLower.get(partnerLower);

    if (msg.type === 'end_chat') {
      if (partnerLower) {
        wipeChatBetween(
          currentSession.lower,
          partnerLower,
          currentSession.username,
          'Chat ended and wiped.'
        );
      }
      return;
    }

    if (!partnerSession) {
      sendToConn(conn, {
        type: 'error',
        code: 'NO_ACTIVE_CHAT',
        message: 'No active chat session with this user.'
      });
      return;
    }

    if (!currentSession.activePartners.has(partnerLower)) {
      currentSession.activePartners.add(partnerLower);
      partnerSession.activePartners.add(currentSession.lower);
      currentSession.incomingRequests.delete(partnerLower);
      currentSession.outgoingRequests.delete(partnerLower);
      partnerSession.incomingRequests.delete(currentSession.lower);
      partnerSession.outgoingRequests.delete(currentSession.lower);
    }

    // ------------------------------------------------------------------------
    // 6. REAL-TIME TEXT CHAT, TYPING INDICATOR & READ RECEIPTS
    // ------------------------------------------------------------------------
    if (msg.type === 'chat_message') {
      const text = typeof msg.text === 'string' ? msg.text.trim() : '';
      if (!text) return;
      if (text.length > MAX_TEXT_LENGTH) {
        sendToConn(conn, {
          type: 'error',
          code: 'MESSAGE_TOO_LONG',
          message: `Message cannot exceed ${MAX_TEXT_LENGTH} characters.`
        });
        return;
      }

      const messageId =
        typeof msg.id === 'string' && msg.id.length <= 64
          ? msg.id
          : crypto.randomUUID();
      const timestamp = Date.now();

      const outbound = {
        type: 'chat_message',
        id: messageId,
        from: currentSession.username,
        to: partnerSession.username,
        text,
        timestamp
      };

      sendToConn(partnerSession.conn, outbound);
      sendToConn(currentSession.conn, {
        type: 'chat_message_ack',
        id: messageId,
        to: partnerSession.username,
        timestamp
      });
      return;
    }

    if (msg.type === 'typing') {
      sendToConn(partnerSession.conn, {
        type: 'typing',
        from: currentSession.username,
        isTyping: Boolean(msg.isTyping),
        timestamp: Date.now()
      });
      return;
    }

    if (msg.type === 'read_receipt') {
      const messageIds = Array.isArray(msg.messageIds)
        ? msg.messageIds.filter((id) => typeof id === 'string').slice(0, 200)
        : [];
      sendToConn(partnerSession.conn, {
        type: 'read_receipt',
        from: currentSession.username,
        messageIds,
        timestamp: Date.now()
      });
      return;
    }

    // ------------------------------------------------------------------------
    // 7. WEBRTC SIGNALING (OFFER, ANSWER, ICE CANDIDATE)
    // ------------------------------------------------------------------------
    if (msg.type === 'rtc_signal') {
      const allowedSignalTypes = new Set(['offer', 'answer', 'ice_candidate', 'renegotiate']);
      if (!allowedSignalTypes.has(msg.signalType)) {
        return;
      }
      sendToConn(partnerSession.conn, {
        type: 'rtc_signal',
        from: currentSession.username,
        signalType: msg.signalType,
        data: msg.data
      });
      return;
    }

    // ------------------------------------------------------------------------
    // 8. CHUNKED FILE RELAY FALLBACK (UP TO 100 MB IN 16 KB CHUNKS)
    // ------------------------------------------------------------------------
    if (msg.type === 'file_meta') {
      const fileId = typeof msg.fileId === 'string' ? msg.fileId.slice(0, 64) : '';
      const size = Number(msg.size) || 0;
      if (!fileId || size <= 0 || size > MAX_FILE_SIZE_BYTES) {
        sendToConn(conn, {
          type: 'error',
          code: 'INVALID_FILE',
          message: 'File size must be between 1 byte and 100 MB.'
        });
        return;
      }
      const safeName = sanitizeFileName(msg.name);
      const mimeType =
        typeof msg.mimeType === 'string' && msg.mimeType.length <= 120
          ? msg.mimeType
          : 'application/octet-stream';
      const totalChunks = Math.ceil(size / CHUNK_SIZE_BYTES);

      sendToConn(partnerSession.conn, {
        type: 'file_meta',
        from: currentSession.username,
        fileId,
        name: safeName,
        size,
        mimeType,
        totalChunks,
        transport: 'relay',
        timestamp: Date.now()
      });
      return;
    }

    if (msg.type === 'file_chunk') {
      const fileId = typeof msg.fileId === 'string' ? msg.fileId.slice(0, 64) : '';
      const chunkIndex = Number(msg.chunkIndex);
      const data = typeof msg.data === 'string' ? msg.data : '';
      if (!fileId || !Number.isInteger(chunkIndex) || chunkIndex < 0 || !data) {
        return;
      }
      if (data.length > 28000) {
        sendToConn(conn, {
          type: 'error',
          code: 'CHUNK_TOO_LARGE',
          message: 'File chunk exceeds 16 KB limit.'
        });
        return;
      }

      sendToConn(partnerSession.conn, {
        type: 'file_chunk',
        from: currentSession.username,
        fileId,
        chunkIndex,
        data
      });
      return;
    }

    if (msg.type === 'file_ack') {
      const fileId = typeof msg.fileId === 'string' ? msg.fileId.slice(0, 64) : '';
      const chunkIndex = Number(msg.chunkIndex);
      if (!fileId || !Number.isInteger(chunkIndex)) return;
      sendToConn(partnerSession.conn, {
        type: 'file_ack',
        from: currentSession.username,
        fileId,
        chunkIndex
      });
      return;
    }

    if (msg.type === 'file_complete') {
      const fileId = typeof msg.fileId === 'string' ? msg.fileId.slice(0, 64) : '';
      if (!fileId) return;
      sendToConn(partnerSession.conn, {
        type: 'file_complete',
        from: currentSession.username,
        fileId,
        timestamp: Date.now()
      });
      return;
    }

    if (msg.type === 'file_cancel') {
      const fileId = typeof msg.fileId === 'string' ? msg.fileId.slice(0, 64) : '';
      if (!fileId) return;
      sendToConn(partnerSession.conn, {
        type: 'file_cancel',
        from: currentSession.username,
        fileId,
        reason: typeof msg.reason === 'string' ? msg.reason.slice(0, 120) : 'Transfer cancelled'
      });
      return;
    }
  }

  // Common security headers compatible with iframe preview & standalone browsers
  const SECURITY_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, HEAD',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
  };

  // Serve index.html, /healthz, and /api/events real-time HTTP fallback on the same port
  const httpServer = http.createServer((req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, SECURITY_HEADERS);
      res.end();
      return;
    }

    const reqUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    if ((req.method === 'GET' || req.method === 'HEAD') && reqUrl.pathname === '/healthz') {
      const body = JSON.stringify({ status: 'ok' });
      res.writeHead(200, {
        ...SECURITY_HEADERS,
        'Content-Length': Buffer.byteLength(body, 'utf8'),
        'Content-Type': 'application/json; charset=utf-8'
      });
      if (req.method === 'HEAD') {
        res.end();
      } else {
        res.end(body);
      }
      return;
    }

    // Fast Online Username Search & Directory Endpoint (GET /api/users?q=...&exclude=...)
    if (req.method === 'GET' && reqUrl.pathname === '/api/users') {
      const q = reqUrl.searchParams.get('q') || '';
      const excludeRaw = normalizeTargetHandle(reqUrl.searchParams.get('exclude') || '').toLowerCase();
      const users = searchOnlineUsers(excludeRaw, q);
      const allUsers = searchOnlineUsers(excludeRaw, '');
      res.writeHead(200, {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json; charset=utf-8'
      });
      res.end(
        JSON.stringify({
          status: 'ok',
          query: q,
          users,
          allUsers,
          totalOnline: usersByLower.size
        })
      );
      return;
    }

    // Real-time HTTP Polling & Event Dispatch Fallback (/api/events)
    if (req.method === 'POST' && reqUrl.pathname === '/api/events') {
      let body = '';
      let aborted = false;
      req.on('data', (chunk) => {
        body += chunk;
        if (body.length > MAX_HTTP_BODY_BYTES) {
          aborted = true;
          res.writeHead(413, {
            ...SECURITY_HEADERS,
            'Content-Type': 'application/json; charset=utf-8'
          });
          res.end(JSON.stringify({ error: 'Payload too large' }));
          req.destroy();
        }
      });

      req.on('end', () => {
        if (aborted) return;
        let payload;
        try {
          payload = body ? JSON.parse(body) : {};
        } catch {
          res.writeHead(400, {
            ...SECURITY_HEADERS,
            'Content-Type': 'application/json; charset=utf-8'
          });
          res.end(JSON.stringify({ error: 'Malformed JSON' }));
          return;
        }

        if (!isSafeJsonObject(payload)) {
          res.writeHead(400, {
            ...SECURITY_HEADERS,
            'Content-Type': 'application/json; charset=utf-8'
          });
          res.end(JSON.stringify({ error: 'Invalid request body' }));
          return;
        }

        const rawConnId =
          typeof payload.connId === 'string' && payload.connId.length <= 80
            ? payload.connId
            : crypto.randomUUID();
        const conn = createVirtualConnection(rawConnId, null);
        conn.lastSeen = Date.now();

        // Automatically bind or restore user session if envelope has username + clientToken
        if (typeof payload.username === 'string' && payload.username.trim()) {
          ensureSessionBound(conn, payload.username, payload.clientToken);
        }

        if (Array.isArray(payload.messages)) {
          for (const m of payload.messages.slice(0, 50)) {
            processProtocolMessage(conn, m);
          }
        }

        const events = conn.outbox.splice(0, conn.outbox.length);
        const boundSession = conn.userLower ? usersByLower.get(conn.userLower) : null;
        const onlineSnapshot = boundSession ? searchOnlineUsers(boundSession.lower, '') : undefined;
        const incomingRequests = boundSession
          ? Array.from(boundSession.incomingRequests).map(
              (l) => usersByLower.get(l)?.username || l
            )
          : undefined;
        const outgoingRequests = boundSession
          ? Array.from(boundSession.outgoingRequests).map(
              (l) => usersByLower.get(l)?.username || l
            )
          : undefined;
        const activePartners = boundSession
          ? Array.from(boundSession.activePartners).map(
              (l) => usersByLower.get(l)?.username || l
            )
          : undefined;

        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Type': 'application/json; charset=utf-8'
        });
        res.end(
          JSON.stringify({
            status: 'ok',
            connId: conn.id,
            events,
            onlineUsers: onlineSnapshot,
            incomingRequests,
            outgoingRequests,
            activePartners,
            totalOnline: usersByLower.size
          })
        );
      });
      return;
    }

    if ((req.method === 'GET' || req.method === 'HEAD') && (reqUrl.pathname === '/' || reqUrl.pathname === '/index.html')) {
      fs.readFile(indexHtmlPath, 'utf8', (err, html) => {
        if (err) {
          res.writeHead(500, {
            ...SECURITY_HEADERS,
            'Content-Type': 'text/plain; charset=utf-8'
          });
          res.end(req.method === 'HEAD' ? undefined : 'Internal Server Error');
          return;
        }
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Length': Buffer.byteLength(html, 'utf8'),
          'Content-Type': 'text/html; charset=utf-8'
        });
        if (req.method === 'HEAD') {
          res.end();
        } else {
          res.end(html);
        }
      });
      return;
    }

    res.writeHead(404, {
      ...SECURITY_HEADERS,
      'Content-Type': 'text/plain; charset=utf-8'
    });
    res.end('Not Found');
  });

  const wss = new WebSocketServer({
    server: httpServer,
    maxPayload: MAX_WS_PAYLOAD_BYTES
  });

  function handleWsDisconnect(conn, reason) {
    conn.ws = null;
    if (!conn.userLower) {
      connectionsById.delete(conn.id);
      return;
    }
    const lower = conn.userLower;
    const session = usersByLower.get(lower);

    // Browser sessions (with clientToken) stay active across mobile tab switches & backgrounding!
    if (session && session.clientToken) {
      conn.hasHttp = true;
      conn.lastSeen = Date.now();
      return;
    }

    conn.userLower = null;
    cleanupUserSession(lower, reason);
    connectionsById.delete(conn.id);
  }

  // ==========================================================================
  // WEBSOCKET CONNECTION HANDLER
  // ==========================================================================
  wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    const reqUrl = new URL(req?.url || '/', 'http://localhost');
    const queryConnId = reqUrl.searchParams.get('connId');
    const connId =
      typeof queryConnId === 'string' && queryConnId.length >= 6 && queryConnId.length <= 80
        ? queryConnId
        : crypto.randomUUID();
    const conn = createVirtualConnection(connId, ws);
    ws.conn = conn;

    ws.on('pong', () => {
      ws.isAlive = true;
      conn.lastSeen = Date.now();
    });

    ws.on('message', (rawBuffer, isBinary) => {
      if (isBinary) {
        sendToConn(conn, {
          type: 'error',
          code: 'INVALID_FORMAT',
          message: 'Binary frames are not supported directly; use JSON protocol.'
        });
        return;
      }

      let msg;
      try {
        msg = JSON.parse(rawBuffer.toString('utf8'));
      } catch {
        sendToConn(conn, {
          type: 'error',
          code: 'BAD_JSON',
          message: 'Malformed JSON payload.'
        });
        return;
      }

      processProtocolMessage(conn, msg);
    });

    ws.on('close', () => {
      handleWsDisconnect(conn, 'socket_closed');
    });

    ws.on('error', () => {
      handleWsDisconnect(conn, 'socket_error');
    });
  });

  // ==========================================================================
  // HEARTBEAT PING / DEAD SOCKET & IDLE HTTP SESSION REAPER
  // ==========================================================================
  const heartbeatTimer = setInterval(() => {
    const now = Date.now();

    for (const ws of wss.clients) {
      if (ws.isAlive === false) {
        const conn = ws.conn;
        if (conn) {
          handleWsDisconnect(conn, 'heartbeat_timeout');
        }
        ws.terminate();
        continue;
      }
      ws.isAlive = false;
      try {
        ws.ping();
      } catch {
        // Ignore ping errors on closing sockets
      }
    }

    // Reap expired sessions after 30 minutes of total inactivity
    for (const [id, conn] of connectionsById.entries()) {
      if (!conn.ws && now - conn.lastSeen > HTTP_SESSION_TIMEOUT_MS) {
        if (conn.userLower) {
          const lower = conn.userLower;
          conn.userLower = null;
          cleanupUserSession(lower, 'http_session_timeout');
        }
        connectionsById.delete(id);
      }
    }
  }, heartbeatIntervalMs);

  heartbeatTimer.unref?.();

  wss.on('close', () => {
    clearInterval(heartbeatTimer);
  });

  return {
    httpServer,
    wss,
    usersByLower,
    close: () =>
      new Promise((resolve) => {
        clearInterval(heartbeatTimer);
        for (const ws of wss.clients) {
          try {
            ws.terminate();
          } catch {
            // ignore
          }
        }
        wss.close(() => {
          httpServer.close(() => resolve());
        });
      })
  };
}

// ============================================================================
// ENTRY POINT WHEN RUN DIRECTLY (`node server.js`)
// ============================================================================
const isMainModule =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(__filename);

if (isMainModule) {
  const { httpServer } = createFastTalkServer();
  httpServer.listen(DEFAULT_PORT, '0.0.0.0', () => {
    console.log(`[Fast Talk] Ephemeral Real-Time Server running on http://0.0.0.0:${DEFAULT_PORT}`);
  });
}
