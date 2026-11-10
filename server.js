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
const DEFAULT_PORT = Number(process.env.PORT) || 3000;
const MAX_WS_PAYLOAD_BYTES = 64 * 1024; // 64 KB max single WS frame (fits 16 KB base64 chunk + JSON header)
const MAX_TEXT_LENGTH = 4000;           // Max characters in a chat message
const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100 MB max file size
const CHUNK_SIZE_BYTES = 16 * 1024;     // 16 KB standard chunk size
const HEARTBEAT_INTERVAL_MS = 15000;    // 15s ping/pong heartbeat check

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
  // Fallback with 6 digits if 9000 guest slots are somehow occupied
  const fallbackNum = crypto.randomInt(100000, 1000000);
  return `Guest_${fallbackNum}`;
}

/**
 * Sliding-window rate limiter kept strictly in memory per socket.
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
// IN-MEMORY EPHEMERAL SERVER FACTORY
// ============================================================================

export function createFastTalkServer(options = {}) {
  const indexHtmlPath = options.indexHtmlPath || path.join(__dirname, 'index.html');
  const heartbeatIntervalMs = options.heartbeatIntervalMs || HEARTBEAT_INTERVAL_MS;

  /**
   * Primary in-memory state:
   * Map<lowerUsername, UserSession>
   * UserSession = {
   *   username: string,
   *   lower: string,
   *   ws: WebSocket,
   *   joinedAt: number,
   *   activePartners: Set<string>,   // lowercase usernames of accepted chat partners
   *   incomingRequests: Set<string>, // lowercase usernames who requested this user
   *   outgoingRequests: Set<string>, // lowercase usernames this user requested
   *   controlLimiter: SlidingWindowLimiter,
   *   chunkLimiter: SlidingWindowLimiter
   * }
   */
  const usersByLower = new Map();

  // Common security headers for all HTTP responses
  const SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
  };

  // Serve index.html and static health check on the same HTTP port
  const httpServer = http.createServer((req, res) => {
    const reqUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    if (req.method === 'GET' && reqUrl.pathname === '/healthz') {
      res.writeHead(200, {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json; charset=utf-8'
      });
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    }

    if (req.method === 'GET' && (reqUrl.pathname === '/' || reqUrl.pathname === '/index.html')) {
      fs.readFile(indexHtmlPath, 'utf8', (err, html) => {
        if (err) {
          res.writeHead(500, {
            ...SECURITY_HEADERS,
            'Content-Type': 'text/plain; charset=utf-8'
          });
          res.end('Internal Server Error');
          return;
        }
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy':
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' blob: data:; media-src 'self' data: blob:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors 'self';"
        });
        res.end(html);
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

  /**
   * Safely sends a JSON payload to a WebSocket if it is open.
   */
  function sendJson(ws, payload) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify(payload));
      } catch {
        // Ignore transient write errors on closing sockets
      }
    }
  }

  /**
   * Builds the list of online users matching a partial query, excluding the requester.
   */
  function searchOnlineUsers(excludeLower, query = '') {
    const cleanQuery = typeof query === 'string' ? query.trim().toLowerCase() : '';
    const results = [];
    for (const [lower, session] of usersByLower.entries()) {
      if (lower === excludeLower) continue;
      if (session.ws.readyState !== WebSocket.OPEN) continue;
      if (!cleanQuery || lower.includes(cleanQuery)) {
        results.push({
          username: session.username,
          joinedAt: session.joinedAt
        });
      }
    }
    results.sort((a, b) => a.username.localeCompare(b.username));
    return results;
  }

  /**
   * Broadcasts the current online user directory to every registered client.
   */
  function broadcastDirectoryUpdate() {
    for (const [lower, session] of usersByLower.entries()) {
      sendJson(session.ws, {
        type: 'online_users',
        users: searchOnlineUsers(lower, ''),
        totalOnline: usersByLower.size
      });
    }
  }

  /**
   * Completely removes a user session from memory, notifies all pending/active partners
   * to wipe shared state, and updates the directory.
   */
  function cleanupUserSession(lower, reason = 'disconnected') {
    const session = usersByLower.get(lower);
    if (!session) return;

    usersByLower.delete(lower);

    // 1. Notify anyone who had a pending request from this user
    for (const targetLower of session.outgoingRequests) {
      const target = usersByLower.get(targetLower);
      if (target) {
        target.incomingRequests.delete(lower);
        sendJson(target.ws, {
          type: 'chat_request_cancelled',
          from: session.username,
          reason
        });
      }
    }

    // 2. Notify anyone who sent a pending request to this user
    for (const requesterLower of session.incomingRequests) {
      const requester = usersByLower.get(requesterLower);
      if (requester) {
        requester.outgoingRequests.delete(lower);
        sendJson(requester.ws, {
          type: 'chat_declined',
          from: session.username,
          reason: 'User went offline.'
        });
      }
    }

    // 3. Notify all active chat partners to immediately wipe messages, files & peer connections
    for (const partnerLower of session.activePartners) {
      const partner = usersByLower.get(partnerLower);
      if (partner) {
        partner.activePartners.delete(lower);
        sendJson(partner.ws, {
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

  /**
   * Wipes an active 1-to-1 chat between two users and notifies both sides.
   */
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
      sendJson(userA.ws, {
        type: 'chat_wiped',
        partner: userB ? userB.username : userBLower,
        initiatedBy: initiatedByUsername,
        reason,
        timestamp
      });
    }
    if (userB) {
      sendJson(userB.ws, {
        type: 'chat_wiped',
        partner: userA ? userA.username : initiatedByUsername,
        initiatedBy: initiatedByUsername,
        reason,
        timestamp
      });
    }
  }

  // ==========================================================================
  // WEBSOCKET CONNECTION HANDLER
  // ==========================================================================
  wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.userLower = null;

    // Pre-registration rate limiter
    const preAuthLimiter = new SlidingWindowLimiter(25, 10000);

    ws.on('pong', () => {
      ws.isAlive = true;
    });

    ws.on('message', (rawBuffer, isBinary) => {
      if (isBinary) {
        sendJson(ws, {
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
        sendJson(ws, {
          type: 'error',
          code: 'BAD_JSON',
          message: 'Malformed JSON payload.'
        });
        return;
      }

      if (!isSafeJsonObject(msg) || typeof msg.type !== 'string') {
        sendJson(ws, {
          type: 'error',
          code: 'MISSING_TYPE',
          message: 'Valid message object and type are required.'
        });
        return;
      }

      // Handle client-level ping
      if (msg.type === 'ping') {
        sendJson(ws, { type: 'pong', timestamp: Date.now() });
        return;
      }

      // ----------------------------------------------------------------------
      // 1. REGISTRATION (Custom username or Guest_1234)
      // ----------------------------------------------------------------------
      if (msg.type === 'register') {
        if (!preAuthLimiter.allow()) {
          sendJson(ws, {
            type: 'register_error',
            message: 'Too many registration attempts. Please wait a moment.'
          });
          return;
        }

        // If socket was already registered as someone else, clean up old session first
        if (ws.userLower && usersByLower.has(ws.userLower)) {
          cleanupUserSession(ws.userLower, 're-registered');
          ws.userLower = null;
        }

        let chosenUsername = '';
        if (msg.isGuest === true) {
          chosenUsername = generateGuestUsername(usersByLower);
        } else {
          const check = validateUsername(msg.username);
          if (!check.valid) {
            sendJson(ws, {
              type: 'register_error',
              message: check.error
            });
            return;
          }
          chosenUsername = check.username;
        }

        const lower = chosenUsername.toLowerCase();
        const existing = usersByLower.get(lower);
        if (existing) {
          if (existing.ws.readyState === WebSocket.OPEN) {
            sendJson(ws, {
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
          ws,
          joinedAt: Date.now(),
          activePartners: new Set(),
          incomingRequests: new Set(),
          outgoingRequests: new Set(),
          controlLimiter: new SlidingWindowLimiter(60, 10000), // 60 control/chat actions per 10s
          chunkLimiter: new SlidingWindowLimiter(1200, 5000)   // 1200 file chunks/acks per 5s (~3.8 MB/s)
        };

        usersByLower.set(lower, session);
        ws.userLower = lower;

        sendJson(ws, {
          type: 'registered',
          username: chosenUsername,
          joinedAt: session.joinedAt,
          users: searchOnlineUsers(lower, ''),
          totalOnline: usersByLower.size
        });

        broadcastDirectoryUpdate();
        return;
      }

      // Require registration for all subsequent message types
      const currentSession = ws.userLower ? usersByLower.get(ws.userLower) : null;
      if (!currentSession) {
        sendJson(ws, {
          type: 'error',
          code: 'UNAUTHORIZED',
          message: 'Please register a username before performing this action.'
        });
        return;
      }

      // Apply separate rate limits for high-frequency file chunks vs control/chat events
      const isChunkTraffic =
        msg.type === 'file_chunk' ||
        msg.type === 'file_ack' ||
        msg.type === 'rtc_signal';

      if (isChunkTraffic) {
        if (!currentSession.chunkLimiter.allow()) {
          sendJson(ws, {
            type: 'error',
            code: 'RATE_LIMIT',
            message: 'File relay rate limit reached. Pausing briefly.'
          });
          return;
        }
      } else {
        if (!currentSession.controlLimiter.allow()) {
          sendJson(ws, {
            type: 'error',
            code: 'RATE_LIMIT',
            message: 'Rate limit exceeded. Please slow down.'
          });
          return;
        }
      }

      // ----------------------------------------------------------------------
      // 2. LOGOUT
      // ----------------------------------------------------------------------
      if (msg.type === 'logout') {
        const lower = currentSession.lower;
        ws.userLower = null;
        cleanupUserSession(lower, 'logged_out');
        sendJson(ws, { type: 'logged_out' });
        return;
      }

      // ----------------------------------------------------------------------
      // 3. LIVE PARTIAL-MATCH USERNAME SEARCH
      // ----------------------------------------------------------------------
      if (msg.type === 'search_users') {
        const query = typeof msg.query === 'string' ? msg.query.slice(0, 40) : '';
        const matches = searchOnlineUsers(currentSession.lower, query);
        sendJson(ws, {
          type: 'search_results',
          query,
          users: matches,
          totalOnline: usersByLower.size
        });
        return;
      }

      // ----------------------------------------------------------------------
      // 4. CHAT REQUEST / CANCEL / ACCEPT / DECLINE
      // ----------------------------------------------------------------------
      if (msg.type === 'chat_request') {
        const targetRaw = typeof msg.to === 'string' ? msg.to.trim() : '';
        const targetLower = targetRaw.toLowerCase();

        if (!targetLower || targetLower === currentSession.lower) {
          sendJson(ws, {
            type: 'error',
            code: 'INVALID_TARGET',
            message: 'Cannot send a chat request to yourself.'
          });
          return;
        }

        const targetSession = usersByLower.get(targetLower);
        if (!targetSession || targetSession.ws.readyState !== WebSocket.OPEN) {
          sendJson(ws, {
            type: 'error',
            code: 'USER_OFFLINE',
            message: `User "${targetRaw}" is no longer online.`
          });
          return;
        }

        if (currentSession.activePartners.has(targetLower)) {
          sendJson(ws, {
            type: 'chat_accepted',
            partner: targetSession.username,
            initiator: true,
            timestamp: Date.now()
          });
          return;
        }

        // If the target already sent a pending request to currentSession, auto-accept
        if (currentSession.incomingRequests.has(targetLower)) {
          currentSession.incomingRequests.delete(targetLower);
          targetSession.outgoingRequests.delete(currentSession.lower);
          currentSession.activePartners.add(targetLower);
          targetSession.activePartners.add(currentSession.lower);

          const now = Date.now();
          sendJson(targetSession.ws, {
            type: 'chat_accepted',
            partner: currentSession.username,
            initiator: true,
            timestamp: now
          });
          sendJson(currentSession.ws, {
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
        sendJson(currentSession.ws, {
          type: 'chat_request_sent',
          to: targetSession.username,
          timestamp
        });

        sendJson(targetSession.ws, {
          type: 'chat_request',
          from: currentSession.username,
          timestamp
        });
        return;
      }

      if (msg.type === 'chat_request_cancel') {
        const targetLower = typeof msg.to === 'string' ? msg.to.trim().toLowerCase() : '';
        const targetSession = usersByLower.get(targetLower);
        currentSession.outgoingRequests.delete(targetLower);
        if (targetSession) {
          targetSession.incomingRequests.delete(currentSession.lower);
          sendJson(targetSession.ws, {
            type: 'chat_request_cancelled',
            from: currentSession.username
          });
        }
        return;
      }

      if (msg.type === 'chat_accept') {
        const requesterRaw = typeof msg.from === 'string' ? msg.from.trim() : '';
        const requesterLower = requesterRaw.toLowerCase();
        const requesterSession = usersByLower.get(requesterLower);

        if (!requesterSession || requesterSession.ws.readyState !== WebSocket.OPEN) {
          currentSession.incomingRequests.delete(requesterLower);
          sendJson(ws, {
            type: 'error',
            code: 'USER_OFFLINE',
            message: `User "${requesterRaw}" went offline before the request could be accepted.`
          });
          return;
        }

        if (!currentSession.incomingRequests.has(requesterLower)) {
          sendJson(ws, {
            type: 'error',
            code: 'NO_REQUEST',
            message: 'No pending chat request found from that user.'
          });
          return;
        }

        currentSession.incomingRequests.delete(requesterLower);
        requesterSession.outgoingRequests.delete(currentSession.lower);

        currentSession.activePartners.add(requesterLower);
        requesterSession.activePartners.add(currentSession.lower);

        const timestamp = Date.now();
        // Original requester acts as WebRTC offer initiator
        sendJson(requesterSession.ws, {
          type: 'chat_accepted',
          partner: currentSession.username,
          initiator: true,
          timestamp
        });
        sendJson(currentSession.ws, {
          type: 'chat_accepted',
          partner: requesterSession.username,
          initiator: false,
          timestamp
        });
        return;
      }

      if (msg.type === 'chat_decline') {
        const requesterRaw = typeof msg.from === 'string' ? msg.from.trim() : '';
        const requesterLower = requesterRaw.toLowerCase();
        const requesterSession = usersByLower.get(requesterLower);

        currentSession.incomingRequests.delete(requesterLower);
        if (requesterSession) {
          requesterSession.outgoingRequests.delete(currentSession.lower);
          sendJson(requesterSession.ws, {
            type: 'chat_declined',
            from: currentSession.username,
            reason: 'Chat request was declined.',
            timestamp: Date.now()
          });
        }
        return;
      }

      // ----------------------------------------------------------------------
      // 5. ACTIVE PARTNER VERIFICATION FOR MESSAGING, WEBRTC & FILE RELAY
      // ----------------------------------------------------------------------
      const partnerRaw = typeof msg.to === 'string' ? msg.to.trim() : '';
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

      if (!partnerSession || !currentSession.activePartners.has(partnerLower)) {
        sendJson(ws, {
          type: 'error',
          code: 'NO_ACTIVE_CHAT',
          message: 'No active chat session with this user.'
        });
        return;
      }

      // ----------------------------------------------------------------------
      // 6. REAL-TIME TEXT CHAT, TYPING INDICATOR & READ RECEIPTS
      // ----------------------------------------------------------------------
      if (msg.type === 'chat_message') {
        const text = typeof msg.text === 'string' ? msg.text.trim() : '';
        if (!text) return;
        if (text.length > MAX_TEXT_LENGTH) {
          sendJson(ws, {
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

        sendJson(partnerSession.ws, outbound);
        sendJson(currentSession.ws, {
          type: 'chat_message_ack',
          id: messageId,
          to: partnerSession.username,
          timestamp
        });
        return;
      }

      if (msg.type === 'typing') {
        sendJson(partnerSession.ws, {
          type: 'typing',
          from: currentSession.username,
          isTyping: Boolean(msg.isTyping),
          timestamp: Date.now()
        });
        return;
      }

      if (msg.type === 'read_receipt') {
        sendJson(partnerSession.ws, {
          type: 'read_receipt',
          from: currentSession.username,
          timestamp: Date.now()
        });
        return;
      }

      // ----------------------------------------------------------------------
      // 7. WEBRTC SIGNALING (OFFER, ANSWER, ICE CANDIDATE)
      // ----------------------------------------------------------------------
      if (msg.type === 'rtc_signal') {
        const allowedSignalTypes = new Set(['offer', 'answer', 'ice_candidate', 'renegotiate']);
        if (!allowedSignalTypes.has(msg.signalType)) {
          return;
        }
        sendJson(partnerSession.ws, {
          type: 'rtc_signal',
          from: currentSession.username,
          signalType: msg.signalType,
          data: msg.data
        });
        return;
      }

      // ----------------------------------------------------------------------
      // 8. CHUNKED FILE RELAY FALLBACK (UP TO 100 MB IN 16 KB CHUNKS)
      // ----------------------------------------------------------------------
      if (msg.type === 'file_meta') {
        const fileId = typeof msg.fileId === 'string' ? msg.fileId.slice(0, 64) : '';
        const size = Number(msg.size) || 0;
        if (!fileId || size <= 0 || size > MAX_FILE_SIZE_BYTES) {
          sendJson(ws, {
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

        sendJson(partnerSession.ws, {
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
        // 16 KB raw = ~21,848 base64 chars; cap at 28,000 chars
        if (data.length > 28000) {
          sendJson(ws, {
            type: 'error',
            code: 'CHUNK_TOO_LARGE',
            message: 'File chunk exceeds 16 KB limit.'
          });
          return;
        }

        sendJson(partnerSession.ws, {
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
        sendJson(partnerSession.ws, {
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
        sendJson(partnerSession.ws, {
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
        sendJson(partnerSession.ws, {
          type: 'file_cancel',
          from: currentSession.username,
          fileId,
          reason: typeof msg.reason === 'string' ? msg.reason.slice(0, 120) : 'Transfer cancelled'
        });
        return;
      }
    });

    ws.on('close', () => {
      if (ws.userLower) {
        const lower = ws.userLower;
        ws.userLower = null;
        cleanupUserSession(lower, 'socket_closed');
      }
    });

    ws.on('error', () => {
      if (ws.userLower) {
        const lower = ws.userLower;
        ws.userLower = null;
        cleanupUserSession(lower, 'socket_error');
      }
    });
  });

  // ==========================================================================
  // HEARTBEAT PING / DEAD SOCKET REAPER
  // ==========================================================================
  const heartbeatTimer = setInterval(() => {
    for (const ws of wss.clients) {
      if (ws.isAlive === false) {
        if (ws.userLower) {
          const lower = ws.userLower;
          ws.userLower = null;
          cleanupUserSession(lower, 'heartbeat_timeout');
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
