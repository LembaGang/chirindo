// The trial recorder. Stub: compiles and answers every call with
// { ok: false, reason: "internal" } until the implementation lands.

import type { TrialRecorder, TrialRecorderOptions } from "./types.js";

export function createTrialRecorder(options: TrialRecorderOptions): TrialRecorder {
  return {
    session_id: "",
    dir: options.dir,
    record: () => ({ ok: false, reason: "internal", paths: [], session_id: "" }),
    reportGap: () => ({ ok: false, reason: "internal" }),
    awaitWitness: async () => ({ ok: false, reason: "internal" }),
    close: async () => {},
  };
}
