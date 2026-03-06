 # seatalk-relay

Lightweight relay service that receives SeaTalk webhooks and forwards events to [openclaw-seatalk](https://github.com/lf4096/openclaw-seatalk) plugin clients via WebSocket.

```
SeaTalk API --HTTP POST-> seatalk-relay <-WebSocket-- openclaw-seatalk (relay mode)
```

## Installation

### From npm

```bash
npm install -g seatalk-relay
seatalk-relay --port 8001
```

Or run without installing:

```bash
npx seatalk-relay --port 8001
```

### From source

```bash
git clone https://github.com/lf4096/seatalk-relay.git
cd seatalk-relay
npm install
npm run build
node dist/seatalk-relay.js
```

For development (auto-loads TypeScript via tsx):

```bash
npm run dev
```

## Configuration

| CLI arg | Env var | Default | Description |
|---|---|---|---|
| `--port` | `PORT` | `8080` | Listen port |
| `--callback-path` | `CALLBACK_PATH` | `/callback` | Webhook endpoint path |
| `--ws-path` | `WS_PATH` | `/ws` | WebSocket endpoint path |

```bash
seatalk-relay --port 8001 --callback-path /seatalk/callback --ws-path /seatalk/ws

# Or use a .env file (Node.js v20.6+)
node --env-file=.env $(which seatalk-relay)
```

## How It Works

1. Plugin connects via WebSocket and sends `{ type: "auth", appId, appSecret, signingSecret }`
2. Relay validates credentials against SeaTalk token API
3. SeaTalk webhooks arrive at the callback path; relay verifies signature using the client's `signingSecret`
4. Verified events are forwarded to the matching client connection
5. `event_verification` challenges are handled directly by the relay

### Duplicate appId Policy

If a new client connects with an appId that already has an active connection, the old connection receives `{ type: "replaced" }` and is closed.

## SeaTalk Setup

Set the Event Callback URL in SeaTalk Open Platform to:

```
https://<your-domain>:<port>/callback
```

Multiple Bot Apps can share the same callback URL — routing is done by `app_id` in the webhook body.
