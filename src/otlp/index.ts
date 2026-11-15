// B-481 T1: OTLP/HTTP trace decoding (N1) and the span mapping. Internal to the
// package for now: the receiver (T2) imports it; no entry in package.json
// "exports" is added by T1.
export {
  OTLP_MAX_BODY_BYTES,
  OTLP_MAX_VALUE_DEPTH,
  OtlpDecodeError,
  decodeTraceJson,
  decodeTraceProtobuf,
  decodeTraceRequest,
} from "./decode.js";
export type {
  DecodedTraceRequest,
  OtlpAnyValue,
  OtlpDecodeReason,
  OtlpEvent,
  OtlpKeyValue,
  OtlpLink,
  OtlpResource,
  OtlpResourceSpans,
  OtlpScope,
  OtlpScopeSpans,
  OtlpSpan,
  OtlpStatus,
} from "./decode.js";
export {
  EXECUTE_TOOL,
  GEN_AI_OPERATION_NAME,
  GEN_AI_TOOL_NAME,
  OTLP_SPAN_TOOL_PREFIX,
  RECEIVER_GATE,
  STATUS_CODE_ERROR,
  canonicalSpan,
  canonicalSpanBytes,
  mapSpan,
  mapTraceBody,
  mapTraceRequest,
  spanOutcome,
  spanToolName,
} from "./map.js";
export type { MappedSpan } from "./map.js";
