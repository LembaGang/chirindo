// `@headlessoracle/chirindo/trial-recorder`: the package entry of the trial
// recorder. ESM only, as the package is.

export { createTrialRecorder } from "./recorder.js";
export type {
  AgentContext,
  AwaitResult,
  Channel,
  GapInput,
  GapReason,
  GapResult,
  RecordInput,
  RecordRefusal,
  RecordResult,
  TrialOrder,
  TrialOrderItem,
  TrialRecorder,
  TrialRecorderOptions,
  TrialWitnessOptions,
} from "./types.js";
