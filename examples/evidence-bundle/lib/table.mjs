// Names the spec fixes: table 3-1's roles and profiles, the check ids of table
// 4-2 in their order, the binding ids, and the verdict texts of table 4-6a.

export const BUNDLE_TYPE = "evidence-bundle/0.9";
export const OUTPUT_TYPE = "evidence-bundle-verdict/0.9";

// Table 3-1, in its row order (the allow-list reports the first role of this
// order that it refuses).
export const ROLE_PROFILES = [
  ["instruction", ["signed-instruction-ed25519/0.2", "vi-0.1-draft", "ap2-0.2"]],
  ["action-arguments", ["jcs-json"]],
  ["action-result", ["jcs-json"]],
  ["gate-log", ["chirindo-evidence.action/1", "jcs-sha256-chain/0.1"]],
  ["gate-receipt", ["eip712-gate-receipt/0.1"]],
  ["issuer-profile", ["chirindo-h4-issuer-profile/2", "chirindo-h4-issuer-profile/1"]],
  ["witness-sidecar", ["chirindo-witness-sidecar/1"]],
  ["checkpoint", ["witness-spec-0.5-checkpoint"]],
  ["witness-receipt", ["witness.checkpoint/1"]],
  ["witness-key", ["ho-v5-keys"]],
  ["operator-key", ["jwk-okp-ed25519", "jwks"]],
  ["payment-transaction", ["eth-rpc-json"]],
  ["payment-receipt", ["eth-rpc-json"]],
  ["payment-block", ["eth-rpc-json"]],
  ["payment-parent-block", ["eth-rpc-json"]],
  ["account-proof", ["eth-proof-json"]],
  ["payment-block-transactions", ["eth-raw-transactions"]],
  ["supporting", ["opaque"]],
];
export const ROLES = ROLE_PROFILES.map(([r]) => r);
export const PROFILES_OF = new Map(ROLE_PROFILES);

export const PAYMENT_ROLES = ["payment-transaction", "payment-receipt", "payment-block", "payment-parent-block", "account-proof", "payment-block-transactions"];

export const BINDING_IDS = ["B-LOG", "B-CKP", "B-WIT", "B-PAY", "B-CHAIN", "B-KEY", "B-INS", "B-GRC"];

export const VERDICT_TEXT = {
  FAILS: "FAILS",
  "DOES-NOT-CONNECT": "DOES NOT CONNECT",
  "PAYMENT-NOT-VERIFIED": "PAYMENT NOT VERIFIED",
  "VERIFIES-OUTSIDE-INSTRUCTION": "VERIFIES, OUTSIDE INSTRUCTION",
  VERIFIES: "VERIFIES",
  "VERIFIES-WITH-GAPS": "VERIFIES WITH GAPS",
};

export const SUPPORTED_CHAINS = [8453n, 84532n];
export const SUPPORTED_TYPES = ["0x0", "0x1", "0x2", "0x4"];

// The two decision triples chirindo writes (spec 4.3, "The cited decision").
export const ALLOW_TRIPLE = ["allow", "executed", "act"];
export const REFUSE_VALUES = ["deny", "denied", "halt"];

export const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
export const THUMBPRINT_RE = /^[A-Za-z0-9_-]{43}$/;
export const LEGACY_KID_RE = /^ed25519\/[A-Za-z0-9_-]{12}$/;
export const UID_RE = /^0x[0-9a-f]{64}$/;
