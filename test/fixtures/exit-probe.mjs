// Test-only preload (node --import, or NODE_OPTIONS=--import) for the tests
// that check how a process ends after network requests (B-329). When
// $EXIT_PROBE_DIR is set it counts this process's fetch() calls and every
// process.exit() made after one, and as the process exits it writes them, with
// the exit code and the resources still active, to
// $EXIT_PROBE_DIR/exit-probe-<pid>.json. fetch and process.exit work as before.
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.env.EXIT_PROBE_DIR;
if (dir !== undefined && dir !== "") {
  let fetches = 0;
  let exitAfterFetch = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (...args) => {
    fetches++;
    return realFetch(...args);
  };
  const realExit = process.exit.bind(process);
  process.exit = (code) => {
    if (fetches > 0) exitAfterFetch++;
    return realExit(code);
  };
  process.on("exit", (code) => {
    writeFileSync(
      join(dir, `exit-probe-${process.pid}.json`),
      JSON.stringify({
        main: process.argv[1] ?? null,
        fetches,
        exitAfterFetch,
        code,
        active: process.getActiveResourcesInfo(),
      }),
    );
  });
}
