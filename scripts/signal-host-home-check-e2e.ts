import { type ChildProcess, spawn } from "node:child_process";
import { createHmac, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { createSocket, type Socket } from "node:dgram";
import { mkdirSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { createServer as createNetServer } from "node:net";
import { resolve } from "node:path";
import { decodeSignalServerMessage } from "@openbot/contracts/signal-protocol/decode";
import type { SignalServerMessage } from "@openbot/contracts/signal-protocol/messages";
import { REMOTE_TICKET_AUDIENCE, REMOTE_TICKET_PROTOCOL_VERSION } from "@openbot/contracts/signal-protocol/ticket";
import { createOpenBotLogger } from "@openbot/logging";
import { exportJWK, SignJWT } from "jose";

const ROOT = resolve(import.meta.dirname, "..");
const OUT = resolve(ROOT, ".openbot-build/signal-host-home-check");
const WAIT_MS = 20_000;
const RETRY_MS = 100;
const HOST_MOVE_AFTER_MS = 1_500;
const HOMED_ELSEWHERE_REASON = "This host has another Signal home.";

const logger = createOpenBotLogger("signal-host-home-check-e2e");

const SESSION_SECRET = randomBytes(32).toString("base64url");
const AUTH_WEBHOOK_SECRET = randomBytes(32).toString("base64url");
const TURN_SECRET = randomBytes(32).toString("base64url");
const METRICS_TOKEN = randomBytes(32).toString("base64url");
const ADMIN_TOKEN = randomBytes(32).toString("base64url");

interface Check {
  name: string;
  passed: boolean;
  evidence: string;
}
const checks: Check[] = [];

function record(name: string, passed: boolean, evidence: string) {
  checks.push({ name, passed, evidence });
  if (passed) logger.info(`PASS ${name}`);
  else logger.error(`FAIL ${name}: ${evidence}`);
}

async function check(name: string, run: () => Promise<string>) {
  try {
    record(name, true, await run());
  } catch (error) {
    record(name, false, error instanceof Error ? error.message : String(error));
  }
}

function expect(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function until(predicate: () => boolean, label: string, limit = WAIT_MS): Promise<void> {
  const deadline = Date.now() + limit;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`Timed out: ${label}.`);
    await new Promise((wake) => setTimeout(wake, 25));
  }
}

function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createNetServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() =>
        typeof address === "object" && address ? resolvePort(address.port) : reject(new Error("No port.")),
      );
    });
  });
}

function hmac(secret: string, text: string) {
  return createHmac("sha256", secret).update(text).digest("base64url");
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => resolveBody(Buffer.concat(chunks).toString()));
    request.on("error", reject);
  });
}

function startTurnServer(): Promise<Socket> {
  const socket = createSocket("udp4");
  socket.on("message", (request, sender) => {
    if (request.length < 20 || request.readUInt32BE(4) !== 0x2112a442) return;
    const header = Buffer.alloc(20);
    header.writeUInt16BE(request.readUInt16BE(0) | 0x0100, 0);
    request.copy(header, 4, 4, 20);
    socket.send(header, sender.port, sender.address);
  });
  return new Promise((resolveSocket) => socket.bind(0, "127.0.0.1", () => resolveSocket(socket)));
}

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const publicJwk = { ...(await exportJWK(publicKey)), kid: "host-home-check-1", alg: "ES256", use: "sig" };

type HomeId = "a" | "b";

interface SessionRecord {
  hostId: string;
  userId: string;
  membershipId: string;
  role: "host" | "member";
  clientPublicKey?: string;
}

const sessions = new Map<string, SessionRecord>();
const storedHomes = new Map<string, HomeId>();
const homeUrls: Record<HomeId, string> = { a: "", b: "" };

function homeOf(url: string): HomeId | null {
  if (url === homeUrls.a) return "a";
  if (url === homeUrls.b) return "b";
  return null;
}

async function ticketFor(sessionId: string, home: HomeId): Promise<string> {
  const session = sessions.get(sessionId);
  if (!session) throw new Error("Unknown session.");
  const now = Math.floor(Date.now() / 1_000);
  return new SignJWT({
    jti: randomUUID(),
    sessionId,
    hostId: session.hostId,
    userId: session.userId,
    membershipId: session.membershipId,
    role: session.role,
    authEpoch: 1,
    protocolMinimum: REMOTE_TICKET_PROTOCOL_VERSION,
    protocolMaximum: REMOTE_TICKET_PROTOCOL_VERSION,
    sessionExpiresAt: now + 86_400,
    signal: home,
    ...(session.clientPublicKey ? { clientPublicKey: session.clientPublicKey } : {}),
  })
    .setProtectedHeader({ alg: "ES256", kid: "host-home-check-1" })
    .setAudience(REMOTE_TICKET_AUDIENCE)
    .setIssuedAt(now - 1)
    .setExpirationTime(now + 300)
    .sign(privateKey);
}

interface HomeCheckCall {
  at: string;
  signal: string;
  hostIds: string[];
  homedElsewhere: string[];
}
const homeCheckCalls: HomeCheckCall[] = [];
const renewals: Array<{ hostId: string; failedHome: HomeId | null; storedHome: HomeId }> = [];

async function renewHost(hostId: string, failedSignalUrl: string | null) {
  const stored = storedHomes.get(hostId) ?? "a";
  const failed = failedSignalUrl ? homeOf(failedSignalUrl) : null;
  const chosen: HomeId = failed === stored ? (stored === "a" ? "b" : "a") : stored;
  storedHomes.set(hostId, chosen);
  renewals.push({ hostId, failedHome: failed, storedHome: chosen });
  return { signalUrl: homeUrls[chosen], ticket: await ticketFor(`host-session-${hostId}`, chosen) };
}

function startControlPlane(port: number): Promise<Server> {
  const server = createServer(async (request, response) => {
    const body = await readBody(request);
    const timestamp = String(request.headers["openbot-timestamp"] ?? "");
    const signed =
      String(request.headers["openbot-signature"] ?? "") === hmac(AUTH_WEBHOOK_SECRET, `${timestamp}.${body}`);
    const path = request.url ?? "";
    const payload = body ? JSON.parse(body) : {};
    const answer = (status: number, value?: unknown) => {
      response.writeHead(status, { "Content-Type": "application/json" });
      response.end(value === undefined ? "" : JSON.stringify(value));
    };
    if (!signed) return answer(401);
    if (path === "/v2/remote/resume/validate-batch") {
      const claims: unknown[] = Array.isArray(payload.claims) ? payload.claims : [];
      return answer(200, { valid: claims.map(() => true) });
    }
    if (path === "/v2/remote/resume/validate") return answer(200, { valid: true });
    if (path === "/v2/remote/signal-hosts/homed-elsewhere") {
      const hostIds: string[] = Array.isArray(payload.hostIds) ? payload.hostIds.map(String) : [];
      const signal = String(payload.signal);
      const homedElsewhere = hostIds.filter((hostId) => {
        const stored = storedHomes.get(hostId);
        return stored !== undefined && stored !== signal;
      });
      homeCheckCalls.push({ at: new Date().toISOString(), signal, hostIds, homedElsewhere });
      return answer(200, { hostIds: homedElsewhere });
    }
    return answer(404);
  });
  return new Promise((resolveServer) => server.listen(port, "127.0.0.1", () => resolveServer(server)));
}

interface Home {
  id: HomeId;
  signalPort: number;
  healthPort: number;
  child: ChildProcess;
}

const serviceOutput: string[] = [];

function spawnHome(id: HomeId, signalPort: number, healthPort: number, controlPlanePort: number, turnPort: number) {
  const child = spawn("bun", [resolve(ROOT, "remote/api/src/index.ts")], {
    cwd: resolve(ROOT, "remote/api"),
    env: {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      REMOTE_SIGNAL_HOST: "127.0.0.1",
      REMOTE_SIGNAL_PORT: String(signalPort),
      REMOTE_HEALTH_HOST: "127.0.0.1",
      REMOTE_HEALTH_PORT: String(healthPort),
      REMOTE_TLS_DISABLED: "true",
      REMOTE_TICKET_PUBLIC_KEYS: JSON.stringify({ keys: [publicJwk] }),
      REMOTE_CONTROL_PLANE_URL: `http://127.0.0.1:${controlPlanePort}`,
      REMOTE_SESSION_SECRET: SESSION_SECRET,
      REMOTE_AUTH_WEBHOOK_SECRET: AUTH_WEBHOOK_SECRET,
      TURN_SHARED_SECRET: TURN_SECRET,
      TURN_HOST: "127.0.0.1",
      TURN_PORT: String(turnPort),
      REMOTE_METRICS_TOKEN: METRICS_TOKEN,
      REMOTE_ADMIN_TOKEN: ADMIN_TOKEN,
      REMOTE_HOST_HOME_CHECK_SECONDS: "1",
      SIGNAL_ID: id,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout?.on("data", (chunk: Buffer) => serviceOutput.push(`[${id}] ${chunk.toString()}`));
  child.stderr?.on("data", (chunk: Buffer) => serviceOutput.push(`[${id}] ${chunk.toString()}`));
  return child;
}

async function waitForReady(home: Home) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (home.child.exitCode !== null) throw new Error(`Signal ${home.id} exited with code ${home.child.exitCode}.`);
    const ready = await fetch(`http://127.0.0.1:${home.signalPort}/health/ready`).then(
      (response) => response.ok,
      () => false,
    );
    if (ready) return;
    await new Promise((wake) => setTimeout(wake, RETRY_MS));
  }
  throw new Error(`Signal ${home.id} did not become ready.`);
}

interface SocketEvent {
  at: string;
  home: HomeId | null;
  event: string;
}

interface ReleasedHost {
  hostId: string;
  url: string;
  token: string;
  socket: WebSocket | null;
  ready: boolean;
  notReadySince: number | null;
  stopped: boolean;
  events: SocketEvent[];
}

function note(host: ReleasedHost, event: string) {
  host.events.push({ at: new Date().toISOString(), home: homeOf(host.url), event });
}

function newReleasedHost(hostId: string): ReleasedHost {
  sessions.set(`host-session-${hostId}`, {
    hostId,
    userId: `owner-${hostId}`,
    membershipId: `${hostId}:host`,
    role: "host",
  });
  return { hostId, url: "", token: "", socket: null, ready: false, notReadySince: null, stopped: false, events: [] };
}

function openHost(host: ReleasedHost) {
  const socket = new WebSocket(host.url);
  host.socket = socket;
  socket.addEventListener("open", () =>
    socket.send(JSON.stringify({ type: "hello", version: 1, peer: "host", token: host.token, multiplex: true })),
  );
  socket.addEventListener("message", (event) => {
    if (host.socket !== socket) return;
    const frame: SignalServerMessage | null = decodeSignalServerMessage(JSON.parse(String(event.data)));
    if (frame?.type !== "ready") return;
    host.ready = true;
    host.notReadySince = null;
    if (frame.resumeToken) host.token = frame.resumeToken;
    note(host, "ready");
  });
  socket.addEventListener("close", (event) => {
    if (host.socket !== socket) return;
    host.socket = null;
    host.ready = false;
    host.notReadySince ??= Date.now();
    note(host, `close ${event.code} ${event.reason}`);
    if (!host.stopped) setTimeout(() => void reconnectHost(host), RETRY_MS);
  });
}

async function reconnectHost(host: ReleasedHost) {
  if (host.stopped || host.socket) return;
  if (host.notReadySince !== null && Date.now() - host.notReadySince >= HOST_MOVE_AFTER_MS) {
    const renewed = await renewHost(host.hostId, host.url);
    host.url = renewed.signalUrl;
    host.token = renewed.ticket;
    host.notReadySince = Date.now();
    note(host, "move after a socket that did not get ready");
  }
  openHost(host);
}

async function startHost(host: ReleasedHost) {
  const renewed = await renewHost(host.hostId, null);
  host.url = renewed.signalUrl;
  host.token = renewed.ticket;
  openHost(host);
  await until(() => host.ready, `${host.hostId} ready`);
}

interface Client {
  sessionId: string;
  url: string;
  socket: WebSocket | null;
  frames: string[];
}

async function startClient(hostId: string): Promise<Client> {
  const sessionId = `client-session-${randomUUID()}`;
  sessions.set(sessionId, {
    hostId,
    userId: `member-${sessionId}`,
    membershipId: `${hostId}:member-${sessionId}`,
    role: "member",
    clientPublicKey: randomBytes(32).toString("base64url"),
  });
  const home = storedHomes.get(hostId) ?? "a";
  const client: Client = { sessionId, url: homeUrls[home], socket: null, frames: [] };
  const token = await ticketFor(sessionId, home);
  const socket = new WebSocket(client.url);
  client.socket = socket;
  socket.addEventListener("open", () =>
    socket.send(JSON.stringify({ type: "hello", version: 1, peer: "client", token, waitForHost: true })),
  );
  socket.addEventListener("message", (event) => {
    const frame = decodeSignalServerMessage(JSON.parse(String(event.data)));
    if (frame) client.frames.push(frame.type);
  });
  socket.addEventListener("close", (event) => client.frames.push(`close ${event.code}`));
  return client;
}

mkdirSync(OUT, { recursive: true });
const [signalPortA, healthPortA, signalPortB, healthPortB, controlPlanePort] = await Promise.all([
  freePort(),
  freePort(),
  freePort(),
  freePort(),
  freePort(),
]);
const plane = await startControlPlane(controlPlanePort);
const turnServer = await startTurnServer();
const turnPort = turnServer.address().port;
homeUrls.a = `ws://127.0.0.1:${signalPortA}/v1/signal`;
homeUrls.b = `ws://127.0.0.1:${signalPortB}/v1/signal`;
const homeA: Home = {
  id: "a",
  signalPort: signalPortA,
  healthPort: healthPortA,
  child: spawnHome("a", signalPortA, healthPortA, controlPlanePort, turnPort),
};
const homeB: Home = {
  id: "b",
  signalPort: signalPortB,
  healthPort: healthPortB,
  child: spawnHome("b", signalPortB, healthPortB, controlPlanePort, turnPort),
};
const stuck = newReleasedHost("host-stuck");
const steady = newReleasedHost("host-steady");
const clients: Client[] = [];

try {
  await Promise.all([waitForReady(homeA), waitForReady(homeB)]);
  logger.info("Both Signal homes are ready.");

  await check("Two released hosts start on home a", async () => {
    await Promise.all([startHost(stuck), startHost(steady)]);
    expect(homeOf(stuck.url) === "a" && homeOf(steady.url) === "a", "A host is not on home a.");
    return "host-stuck and host-steady are ready on a";
  });

  await check("A lost move answer leaves host-stuck on a while its stored home is b", async () => {
    storedHomes.set(stuck.hostId, "b");
    const client = await startClient(stuck.hostId);
    clients.push(client);
    await until(() => client.frames.includes("host-waiting"), "client waits on b");
    expect(homeOf(client.url) === "b", `client went to ${homeOf(client.url)}`);
    expect(stuck.ready && homeOf(stuck.url) === "a", "host-stuck is not ready on a.");
    return "the client of host-stuck goes to b and waits; host-stuck stays ready on a";
  });

  await check("Signal a closes host-stuck because the account service names another home", async () => {
    await until(
      () => stuck.events.some((event) => event.home === "a" && event.event === `close 1013 ${HOMED_ELSEWHERE_REASON}`),
      "host-stuck closed on a",
    );
    const call = homeCheckCalls.find((candidate) => candidate.homedElsewhere.includes(stuck.hostId));
    expect(call?.signal === "a", `home check calls: ${JSON.stringify(homeCheckCalls)}`);
    expect(call.hostIds.includes(steady.hostId), "Signal a did not send host-steady in the check.");
    return `Signal a sent ${JSON.stringify(call.hostIds)}; the account service named ${JSON.stringify(call.homedElsewhere)}`;
  });

  await check("Signal a refuses the resume of host-stuck, and the released host moves to b", async () => {
    await until(() => stuck.ready && homeOf(stuck.url) === "b", "host-stuck ready on b");
    const refusals = stuck.events.filter(
      (event) => event.home === "a" && event.event === `close 1013 ${HOMED_ELSEWHERE_REASON}`,
    ).length;
    const readyOnAAfterClose = stuck.events
      .slice(stuck.events.findIndex((event) => event.event.startsWith("close 1013")))
      .some((event) => event.home === "a" && event.event === "ready");
    expect(refusals >= 2, `only ${refusals} refusal on a`);
    expect(!readyOnAAfterClose, "host-stuck got ready on a again after the close.");
    const move = renewals.findLast((renewal) => renewal.hostId === stuck.hostId);
    expect(move?.failedHome === "a" && move.storedHome === "b", `last renewal ${JSON.stringify(move)}`);
    return `${refusals} closes on a, then a renewal with failed home a moved host-stuck to b`;
  });

  await check("The waiting client on b reaches host-stuck", async () => {
    const client = clients[0];
    expect(client !== undefined, "No client.");
    await until(() => client.frames.includes("ready"), "client ready on b");
    return `client frames: ${client.frames.join(", ")}`;
  });

  await check("host-steady, whose stored home is a, stays on a with no close", async () => {
    await new Promise((wake) => setTimeout(wake, 2_500));
    const closes = steady.events.filter((event) => event.event.startsWith("close"));
    expect(closes.length === 0 && steady.ready && homeOf(steady.url) === "a", JSON.stringify(steady.events));
    const checked = homeCheckCalls.filter((call) => call.hostIds.includes(steady.hostId)).length;
    expect(checked >= 2, `host-steady was in ${checked} checks`);
    return `host-steady was in ${checked} checks and got no close`;
  });
} catch (error) {
  record("scenario", false, error instanceof Error ? error.message : String(error));
} finally {
  stuck.stopped = true;
  steady.stopped = true;
  stuck.socket?.close();
  steady.socket?.close();
  for (const client of clients) client.socket?.close();
  homeA.child.kill("SIGTERM");
  homeB.child.kill("SIGTERM");
  plane.close();
  turnServer.close();
}

const passed = checks.length > 0 && checks.every((entry) => entry.passed);
const report = {
  generatedAt: new Date().toISOString(),
  passed,
  checks,
  homeCheckCalls,
  renewals,
  hostEvents: { [stuck.hostId]: stuck.events, [steady.hostId]: steady.events },
  clientFrames: clients.map((client) => client.frames),
  serviceOutput: passed ? [] : serviceOutput.slice(-80),
};
writeFileSync(resolve(OUT, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
logger.info(`Report: ${resolve(OUT, "report.json")}`);
process.exit(passed ? 0 : 1);
