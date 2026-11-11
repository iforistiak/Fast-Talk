# Fast Talk

**Fast Talk** is a private, ephemeral 1-to-1 real-time communication and direct file sharing workspace built for zero-trace collaboration. It requires no accounts, uses no database, and automatically erases all session data the moment a conversation ends.

---

## Ephemeral Architecture & Security Principles

Fast Talk is engineered around strict data minimization and zero persistence:

- **Zero Database & Zero Disk Writes**: Active sessions exist strictly in volatile memory for the duration of a live connection. Nothing is ever logged or written to disk.
- **Zero Client Storage**: No conversation history, usernames, or shared files are stored in browser storage (`localStorage`, `sessionStorage`, or `IndexedDB`).
- **Bilateral Session Wipe**: When either participant clicks **End chat & wipe**, logs out, or closes/refreshes their browser tab, all messages, shared files, and temporary object URLs are immediately destroyed for both users.
- **Defense-in-Depth Input & Traffic Controls**:
  - Strict validation on usernames (`3–20` alphanumeric characters and underscores) with case-insensitive collision protection.
  - Complete HTML escaping on all user-supplied text and path-traversal sanitization on all shared file names.
  - Strict HTTP security headers (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`).
  - Per-session sliding-window rate limiting, frame size caps, and automated dead-connection cleanup.

---

## Core Features

- **Instant Session Entry**: Choose a unique username or join immediately with an auto-generated Guest handle (`Guest_XXXX`).
- **Share Invite Link & QR Code Discovery**: Generate a scannable QR code and direct invite link (`?invite=username`) so peers can connect by scanning with a mobile camera or opening the link.
- **Live Online Directory & Search**: Real-time partial-match search across currently online peers.
- **Consent-First 1-to-1 Requests**: Send, accept, decline, or cancel conversation requests before any messages or files can be exchanged.
- **Real-Time Messaging & Presence**:
  - Instant text delivery with timestamps (`HH:MM:SS`).
  - Animated wave-dot typing indicator when your partner is composing a message.
  - Double-check read receipts (`Sent` single check and `Read` double check) updated live when your partner views the active conversation.
  - Focus-aware notification sound effect with a mute/unmute toggle.
  - Unread message badges across active conversations.
- **Direct File Sharing (Up to 100 MB)**:
  - Live transfer progress bar and percentage status.
  - Mid-transfer cancellation from either side.
  - Inline image preview and one-click file download.
- **Responsive Dual-Theme Interface**:
  - Mobile-first single-pane navigation with bottom-fixed controls and `>= 44px` touch targets, expanding to a split sidebar and workspace layout on tablets and desktops.
  - Instant switching between Light and Dark corporate themes.

---

## Installation & Run Instructions

### Prerequisites

- A standard JavaScript server runtime (`v18+` recommended).

### 1. Install Dependencies

```bash
npm install
```

### 2. Start the Application

```bash
npm start
```

By default, the server listens on port `3000` (or the port specified via the `PORT` environment variable):

```bash
PORT=3000 npm start
```

Open `http://localhost:3000` in your browser. To test 1-to-1 chat and QR invite discovery locally, open a second browser window or scan the generated invite QR code.

### 3. Static Hosting (GitHub Pages, Vercel, Netlify)

When deployed on static hosts like **GitHub Pages** (`https://<username>.github.io/<repo>/`):
- Multi-tier client-side signaling automatically enables local discovery, mutual request auto-pairing, and WebRTC handshakes.
- For internet-wide cross-device connections on static hosts, configure your Supabase Realtime credentials in `SUPABASE_CONFIG` at the top of `index.html` or directly in the UI via the **Relay** navigation button.
- Alternatively, deploy `server.js` to any free Node host (such as Render, Railway, or Fly.io) and connect from your static site by entering your `wss://...` URL in the Relay settings modal.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](./LICENSE) file for full details.

Copyright (c) 2026 **MD. ISTIAK ISLAM**

---

**Ideas Deployed By - MD. ISTIAK ISLAM**
