// Public types of the Chirindo trial recorder (`@headlessoracle/chirindo/trial-recorder`).
// Every result is a plain object with an `ok` member; nothing here throws after
// createTrialRecorder has returned.

export interface TrialWitnessOptions {
  // https://, or http:// for a loopback host only (as `chirindo proxy --witness`).
  baseUrl: string;
  // The expected `witness` member of every receipt.
  name: string;
  // The witness's public key: 64 hex characters, or the path of a JWK file
  // (as `--witness-key` accepts). Strongly recommended: without it the key is
  // fetched from <baseUrl>/v5/keys for each receipt.
  pinnedKey?: string;
  // The path of a file holding an Evidence plan account key (whitespace
  // trimmed). The library reads it; the key is never logged.
  accountKeyFile?: string;
}

export interface TrialRecorderOptions {
  // The data directory; `chirindo init --dir <dir>` creates its identity.
  dir: string;
  // The `server` member of every entry.
  serverLabel: string;
  // https URL of the operator's published JWKS, stamped into every entry.
  jwksUri?: string;
  witness?: TrialWitnessOptions;
  // One line per call; defaults to stderr. Never given a key or a value.
  logger?: (line: string) => void;
  // For tests only: the clock for entry, checkpoint, gap and timing times.
  now?: () => string;
}

export type Channel = "acp" | "ucp" | "ap2" | "mcp" | "stripe-approval-hook" | "other";

export interface AgentContext {
  channel?: Channel;
  platform_signature?: { header_name: string; value: string; key_id?: string; alg?: string };
  payment_token_limits?: { currency: string; max_amount_minor: string; expires_at?: string };
  agent_name?: string;
  mandate?: { format: "ap2" | "vi" | "other"; value: string };
}

export interface TrialOrderItem {
  sku: string;
  quantity: number;
  unit_price_minor: string;
  name?: string;
  category?: string;
  refundable?: boolean;
  service_from?: string;
  service_until?: string;
  location?: string;
}

// The committed order of spec v0.10 section 4.3.
export interface TrialOrder {
  merchant_id: string;
  merchant_order_id?: string;
  checkout_ref?: string;
  currency: string;
  total_minor: string;
  items: TrialOrderItem[];
}

export interface RecordInput {
  order_ref: string;
  order: TrialOrder;
  agent_context?: AgentContext;
  // A non-negative integer the caller increments per call.
  call_seq?: number;
}

export type RecordRefusal =
  | "invalid-input"
  | "refused-field"
  | "refused-value"
  | "invalid-order"
  | "write-failed"
  | "internal";

export type RecordResult =
  | { ok: true; entry_hash: string; args_hash: string; count: number; session_id: string }
  // `paths` holds RFC 6901 pointers of the members that decided it, never values.
  | { ok: false; reason: RecordRefusal; paths: string[]; session_id: string };

export type GapReason = "caller-timeout" | "unreachable" | "other";

export interface GapInput {
  order_ref: string;
  call_seq?: number;
  reason: GapReason;
}

export type GapResult = { ok: true } | { ok: false; reason: "invalid-input" | "write-failed" | "internal" };

export type AwaitResult =
  | { ok: true; received_at: string; covering_count: number }
  | { ok: false; reason: "timeout" | "no-witness" | "unknown-entry" | "stopped" | "closed" | "internal" };

export interface TrialRecorder {
  readonly session_id: string;
  readonly dir: string;
  record(input: RecordInput): RecordResult;
  reportGap(input: GapInput): GapResult;
  // maxMs is capped at 3,500.
  awaitWitness(entry_hash: string, maxMs: number): Promise<AwaitResult>;
  // Default 5,000 ms.
  close(timeoutMs?: number): Promise<void>;
}
