// JSON-RPC transport to the integrator's endpoint. The SDK's rpc.Server cannot
// take an injected fetch or cap the response size, so Guard posts directly.

export const DEFAULT_RPC_TIMEOUT_MS = 10_000;
export const MAX_RPC_TIMEOUT_MS = 60_000;

const REQUEST_ID = 1;

/** RPC endpoint chosen by the integrator. Guard has no default endpoint. */
export interface RpcConfig {
  url: string;
  /** Deadline for each exchange (request and response body). */
  timeoutMs?: number;
  /** Defaults to the global fetch. */
  fetch?: typeof fetch;
}

/** Why one HTTP exchange produced no usable body, whatever its protocol. */
export type ExchangeFailure =
  | { status: "timeout"; timeoutMs: number }
  | { status: "error"; reason: "invalid_config" | "network" | "http"; httpStatus?: number }
  | { status: "malformed"; reason: "too_large" | "invalid_json" };

/** Why an exchange produced no usable JSON-RPC result. Carries no RPC-provided prose. */
export type TransportFailure =
  | ExchangeFailure
  | { status: "error"; reason: "rpc"; httpStatus?: number; rpcCode?: number }
  | { status: "malformed"; reason: "invalid_shape" };

export type RpcReply = { ok: true; result: Record<string, unknown> } | { ok: false; failure: TransportFailure };

/**
 * Posts one JSON-RPC request and returns its `result` object. Never throws.
 * Anything other than a well-formed JSON-RPC success is a failure, never a guess.
 */
export async function callRpc(rpc: RpcConfig, method: string, params: Record<string, unknown>, maxBytes: number): Promise<RpcReply> {
  const reply = await postJson(rpc, JSON.stringify({ jsonrpc: "2.0", id: REQUEST_ID, method, params }), maxBytes);
  return reply.ok ? envelope(reply.json) : reply;
}

export type JsonReply = { ok: true; json: unknown } | { ok: false; failure: ExchangeFailure };

/**
 * POSTs `body` to `target.url` as JSON and parses one response body. Never
 * throws. Shared by the RPC transport and Intel's API so both get the same
 * deadline, byte cap and redirect policy; the response's own meaning is the
 * caller's to check. A non-2xx status is a failure with its `httpStatus`.
 */
export async function postJson(target: RpcConfig, body: string, maxBytes: number): Promise<JsonReply> {
  const timeoutMs = target.timeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;
  const fetchImpl = target.fetch ?? globalThis.fetch;
  if (!validEndpoint(target.url) || !validTimeout(timeoutMs) || typeof fetchImpl !== "function") {
    return fail({ status: "error", reason: "invalid_config" });
  }

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  // Raced rather than relying on the signal alone: an injected fetch may ignore it.
  const deadline = new Promise<JsonReply>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve(fail({ status: "timeout", timeoutMs }));
    }, timeoutMs);
  });
  try {
    return await Promise.race([exchange(fetchImpl, target.url, body, maxBytes, controller.signal), deadline]);
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

const fail = (failure: ExchangeFailure): JsonReply => ({ ok: false, failure });

async function exchange(fetchImpl: typeof fetch, url: string, body: string, maxBytes: number, signal: AbortSignal): Promise<JsonReply> {
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      signal,
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      cache: "no-store",
    });
  } catch {
    return fail({ status: "error", reason: "network" });
  }
  if (!response.ok) {
    return fail({ status: "error", reason: "http", httpStatus: response.status });
  }
  try {
    const text = await readCapped(response, maxBytes);
    if (!text.ok) return fail({ status: "malformed", reason: text.reason });
    try {
      return { ok: true, json: JSON.parse(text.text) };
    } catch {
      return fail({ status: "malformed", reason: "invalid_json" });
    }
  } catch {
    // Body stream failed (including abort after the deadline).
    return fail({ status: "error", reason: "network" });
  }
}

function envelope(json: unknown): RpcReply {
  const malformed: RpcReply = { ok: false, failure: { status: "malformed", reason: "invalid_shape" } };
  if (!isRecord(json) || json["jsonrpc"] !== "2.0" || json["id"] !== REQUEST_ID) return malformed;
  if (Object.hasOwn(json, "error")) {
    const err = json["error"];
    if (!isRecord(err) || !Number.isSafeInteger(err["code"])) return malformed;
    return { ok: false, failure: { status: "error", reason: "rpc", rpcCode: err["code"] as number } };
  }
  const result = json["result"];
  return isRecord(result) ? { ok: true, result } : malformed;
}

type Body = { ok: true; text: string } | { ok: false; reason: "too_large" | "invalid_json" };

/** Reads the body as UTF-8, stopping as soon as it exceeds `maxBytes`. */
async function readCapped(response: Response, maxBytes: number): Promise<Body> {
  const declared = response.headers.get("content-length");
  if (declared !== null && /^\d+$/.test(declared) && Number(declared) > maxBytes) {
    await response.body?.cancel().catch(() => undefined);
    return { ok: false, reason: "too_large" };
  }
  const decoder = new TextDecoder("utf-8", { fatal: true });
  if (response.body === null) {
    const text = await response.text();
    return new TextEncoder().encode(text).byteLength > maxBytes ? { ok: false, reason: "too_large" } : { ok: true, text };
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return { ok: false, reason: "too_large" };
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.byteLength;
  }
  try {
    return { ok: true, text: decoder.decode(bytes) };
  } catch {
    return { ok: false, reason: "invalid_json" };
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isLedger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
}

function validEndpoint(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

function validTimeout(ms: number): boolean {
  return Number.isFinite(ms) && ms > 0 && ms <= MAX_RPC_TIMEOUT_MS;
}
