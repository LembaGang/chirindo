// B-481 T3 (rev 2): the one way a test starts the receiver command. The
// command's witness is ON by default and points at Headless Oracle's live
// service, so a test may start it only with the witness turned off
// (--no-witness), pointed at a loopback stub (--witness http://127.0.0.1...),
// or with an injected POST (witnessSeams.post: nothing goes on the network).
// Any other call is refused before the command runs. test/otel-checkpoint.test.ts
// holds the test that no test file calls the command but through this helper.

import { startOtelReceiverCommand, type OtelCommandArgs, type OtelCommandIo, type OtelCommandStarted } from "../src/otel/command.js";

const LOOPBACK_URL = /^http:\/\/(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|\[::1\])(:\d{1,5})?(\/|$)/;

// Why this call may start the command, or null when it may not.
export function witnessChoice(args: OtelCommandArgs, io: OtelCommandIo): string | null {
  if (args.flags.get("no-witness") === true) return "--no-witness";
  const w = args.flags.get("witness");
  if (typeof w === "string" && LOOPBACK_URL.test(w)) return "a loopback --witness";
  if (io.witnessSeams?.post !== undefined) return "an injected POST";
  return null;
}

export async function startCommandForTest(args: OtelCommandArgs, io: OtelCommandIo): Promise<OtelCommandStarted> {
  if (witnessChoice(args, io) === null) {
    throw new Error("test guard: the receiver command starts in a test only with --no-witness, a loopback --witness, or an injected POST (its default witness is the live service)");
  }
  return startOtelReceiverCommand(args, io);
}
