import * as crypto from "node:crypto";
import * as http from "node:http";
import { parseArgs } from "node:util";
import { type WebSocket, WebSocketServer } from "ws";

const { values: args } = parseArgs({
	options: {
		port: { type: "string", default: process.env.PORT ?? "8080" },
		"callback-path": { type: "string", default: process.env.CALLBACK_PATH ?? "/callback" },
		"ws-path": { type: "string", default: process.env.WS_PATH ?? "/ws" },
		help: { type: "boolean", short: "h", default: false },
	},
});

if (args.help) {
	console.log(`seatalk-relay - SeaTalk webhook relay service

Usage: seatalk-relay [options]

Options:
  --port <port>                Listen port (env: PORT, default: 8080)
  --callback-path <path>       Webhook endpoint path (env: CALLBACK_PATH, default: /callback)
  --ws-path <path>             WebSocket endpoint path (env: WS_PATH, default: /ws)
  -h, --help                   Show this help message`);
	process.exit(0);
}

const PORT = Number(args.port);
const CALLBACK_PATH = args["callback-path"]!;
const WS_PATH = args["ws-path"]!;

type ClientEntry = {
	ws: WebSocket;
	appId: string;
	appSecret: string;
	signingSecret: string;
};

type RelayMessage = { type: "auth"; appId: string; appSecret: string; signingSecret: string };

const clients = new Map<string, ClientEntry>();

function verifySignature(rawBody: Buffer, signingSecret: string, signature: string): boolean {
	const secretBytes = Buffer.from(signingSecret, "latin1");
	const calculated = crypto
		.createHash("sha256")
		.update(Buffer.concat([rawBody, secretBytes]))
		.digest("hex");
	try {
		return crypto.timingSafeEqual(
			Buffer.from(calculated, "hex"),
			Buffer.from(signature, "hex"),
		);
	} catch {
		return false;
	}
}

const SEATALK_TOKEN_URL = "https://openapi.seatalk.io/auth/app_access_token";
const AUTH_TIMEOUT_MS = 10_000;

async function validateCredentials(appId: string, appSecret: string): Promise<boolean> {
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), AUTH_TIMEOUT_MS);
	try {
		const res = await fetch(SEATALK_TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ app_id: appId, app_secret: appSecret }),
			signal: controller.signal,
		});
		if (!res.ok) return false;
		const data = (await res.json()) as { code: number };
		return data.code === 0;
	} catch {
		return false;
	} finally {
		clearTimeout(timeout);
	}
}

const MAX_BODY_BYTES = 1024 * 1024;

function readBody(req: http.IncomingMessage): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		let received = 0;
		const chunks: Buffer[] = [];
		req.on("data", (chunk: Buffer) => {
			received += chunk.length;
			if (received > MAX_BODY_BYTES) {
				req.destroy(new Error("Request body too large"));
				return;
			}
			chunks.push(chunk);
		});
		req.on("end", () => resolve(Buffer.concat(chunks)));
		req.on("error", reject);
	});
}

function setupClientAuth(ws: WebSocket): void {
	const authTimer = setTimeout(() => {
		log("ws: auth timeout, closing");
		ws.close(4001, "auth timeout");
	}, 10_000);

	ws.once("message", async (raw) => {
		clearTimeout(authTimer);
		let msg: RelayMessage;
		try {
			msg = JSON.parse(String(raw));
		} catch {
			send(ws, { type: "auth_fail", error: "invalid JSON" });
			ws.close(4002, "invalid JSON");
			return;
		}

		if (msg.type !== "auth" || !msg.appId || !msg.appSecret || !msg.signingSecret) {
			send(ws, {
				type: "auth_fail",
				error: "expected auth message with appId, appSecret, signingSecret",
			});
			ws.close(4003, "bad auth");
			return;
		}

		const valid = await validateCredentials(msg.appId, msg.appSecret);
		if (!valid) {
			send(ws, { type: "auth_fail", error: "invalid SeaTalk credentials" });
			ws.close(4004, "invalid credentials");
			return;
		}

		const existing = clients.get(msg.appId);
		if (existing) {
			log(`ws: replacing existing connection for appId=${msg.appId}`);
			send(existing.ws, { type: "replaced" });
			existing.ws.close(4005, "replaced by new connection");
			clients.delete(msg.appId);
		}

		const entry: ClientEntry = {
			ws,
			appId: msg.appId,
			appSecret: msg.appSecret,
			signingSecret: msg.signingSecret,
		};
		clients.set(msg.appId, entry);
		send(ws, { type: "auth_ok" });
		log(`ws: client authenticated appId=${msg.appId} (total=${clients.size})`);

		ws.on("error", (err) => {
			log(`ws: error appId=${msg.appId}: ${err.message}`);
		});

		ws.on("close", () => {
			if (clients.get(msg.appId)?.ws === ws) {
				clients.delete(msg.appId);
				log(`ws: client disconnected appId=${msg.appId} (total=${clients.size})`);
			}
		});
	});
}

async function handleWebhook(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
	let rawBody: Buffer;
	try {
		rawBody = await readBody(req);
	} catch {
		res.writeHead(400);
		res.end("Bad Request");
		return;
	}

	let body: { event_id?: string; event_type?: string; app_id?: string; event?: any };
	try {
		body = JSON.parse(rawBody.toString("utf-8"));
	} catch {
		res.writeHead(400);
		res.end("Invalid JSON");
		return;
	}

	const appId = body.app_id;
	if (!appId) {
		res.writeHead(400);
		res.end("Missing app_id");
		return;
	}

	const client = clients.get(appId);

	if (body.event_type === "event_verification") {
		const challenge = (body.event as { seatalk_challenge?: string })?.seatalk_challenge;
		if (!challenge) {
			res.writeHead(400);
			res.end("Missing challenge");
			return;
		}
		if (client) {
			const signature = req.headers.signature as string | undefined;
			if (!signature || !verifySignature(rawBody, client.signingSecret, signature)) {
				res.writeHead(403);
				res.end("Forbidden");
				return;
			}
		}
		res.writeHead(200, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ seatalk_challenge: challenge }));
		log(`webhook: challenge responded for appId=${appId}`);
		return;
	}

	if (!client) {
		log(`webhook: no client connected for appId=${appId}, dropping event`);
		res.writeHead(200);
		res.end("OK");
		return;
	}

	const signature = req.headers.signature as string | undefined;
	if (!signature || !verifySignature(rawBody, client.signingSecret, signature)) {
		log(`webhook: signature verification failed for appId=${appId}`);
		res.writeHead(403);
		res.end("Forbidden");
		return;
	}

	res.writeHead(200);
	res.end("OK");

	send(client.ws, { type: "event", event: body });
	log(`webhook: forwarded ${body.event_type} to appId=${appId}`);
}

function send(ws: WebSocket, data: Record<string, unknown>): void {
	if (ws.readyState === ws.OPEN) {
		ws.send(JSON.stringify(data));
	}
}

function log(msg: string): void {
	const ts = new Date().toISOString().slice(11, 19);
	console.log(`${ts} ${msg}`);
}

const PING_INTERVAL_MS = 30_000;

function startHeartbeat(): void {
	setInterval(() => {
		for (const [appId, entry] of clients) {
			if (entry.ws.readyState !== entry.ws.OPEN) {
				clients.delete(appId);
				continue;
			}
			send(entry.ws, { type: "ping" });
		}
	}, PING_INTERVAL_MS);
}

const server = http.createServer();
const wss = new WebSocketServer({ noServer: true });

server.on("request", async (req, res) => {
	const pathname = new URL(req.url ?? "/", `http://localhost:${PORT}`).pathname;
	if (req.method === "POST" && pathname === CALLBACK_PATH) {
		await handleWebhook(req, res).catch((err) => {
			console.error("webhook error:", err);
			if (!res.headersSent) {
				res.writeHead(500);
				res.end("Internal Server Error");
			}
		});
		return;
	}
	res.writeHead(404);
	res.end("Not Found");
});

server.on("upgrade", (req, socket, head) => {
	const pathname = new URL(req.url ?? "/", `http://localhost:${PORT}`).pathname;
	if (pathname !== WS_PATH) {
		socket.destroy();
		return;
	}
	wss.handleUpgrade(req, socket, head, (ws) => {
		setupClientAuth(ws);
	});
});

server.listen(PORT, () => {
	log(`seatalk-relay listening on port ${PORT}`);
	log(`  webhook: ${CALLBACK_PATH}`);
	log(`  websocket: ${WS_PATH}`);
});

startHeartbeat();
