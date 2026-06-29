export { PRODUCT_NAME } from "./brand.js";
export {
  RECORD_VERSION,
  contentOf,
  checkpointContentOf,
} from "./record.js";
export type {
  AgentInfo,
  CheckpointContent,
  Decision,
  DecisionSource,
  EventType,
  FileEditEvent,
  FileReadEvent,
  GateBlock,
  McpCallEvent,
  Outcome,
  RecordContent,
  RecordEvent,
  RecordVersion,
  ShellEvent,
  SignedCheckpoint,
  SignedRecord,
  ToolCallEvent,
} from "./record.js";
export { jcs, jcsBytes } from "./canonicalize.js";
export {
  argsHash,
  argsHashFromJsonString,
  entryHashOfCanonical,
  genesisInput,
  genesisPrevHash,
  resultHash,
  resultHashFromJsonString,
  sha256Hex,
} from "./hash.js";
export type { GenesisInput } from "./hash.js";
export {
  base64UrlDecode,
  base64UrlNoPad,
  signEd25519,
  verifyEd25519,
} from "./sign.js";
export {
  ed25519PrivateKeyFromSeed,
  generateKeyPair,
  publicKeyBase64Url,
  publicKeyFromPrivate,
  rawPublicKeyBytes,
} from "./key.js";
export { Chain, type ChainOptions } from "./chain.js";
export {
  requestCommitment,
  requestDescriptor,
} from "./request.js";
export type {
  FileEditDescriptor,
  FileReadDescriptor,
  McpCallDescriptor,
  RequestDescriptor,
  ShellDescriptor,
  ToolCallDescriptor,
} from "./request.js";

// Identity + chain file IO — exposed so consumers (e.g. the MCP gate)
// can write records using the same primitives the recorder uses.
export {
  IDENTITY_FILENAME,
  PRIVATE_KEY_FILENAME,
  buildIdentityFile,
  loadFullIdentity,
  loadIdentity,
  makeKid,
  readIdentityFile,
  writeIdentity,
} from "./identity.js";
export type {
  IdentityFile,
  LoadedFullIdentity,
  LoadedIdentity,
  WriteIdentityResult,
} from "./identity.js";
export {
  ChainParseError,
  appendRecordLine,
  parseChainJsonl,
  readChainFile,
  readChainFileOrEmpty,
  serializeChainJsonl,
  writeChainFile,
} from "./io.js";
export type { ChainFile } from "./io.js";
export { runInit } from "./cli/init.js";
export type { InitOptions, InitResult } from "./cli/init.js";
export {
  formatVerifyResult,
  runVerify,
} from "./cli/verify.js";
export type {
  TamperReason,
  VerifyOptions,
  VerifyOptionsJwks,
  VerifyOptionsKey,
  VerifyResult,
} from "./cli/verify.js";
export {
  DEFAULT_JWKS_URL,
  JWKS_URL_ENV_VAR,
  _clearJwksCache,
  _setJwksCacheEntry,
  buildJwk,
  buildJwks,
  ed25519PublicKeyFromJwk,
  fetchJwks,
  findJwkByKid,
  resolveKeyFromJwks,
} from "./jwks.js";
export type {
  Jwk,
  Jwks,
  JwksResolveError,
  JwksResolveResult,
} from "./jwks.js";
