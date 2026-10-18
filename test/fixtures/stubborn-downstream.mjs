// A downstream that outlives its kill, for test/cli-proxy-exit.test.ts: it
// ignores SIGTERM, never reads its stdin and stays up for 20 s, so a proxy
// that waited for it to exit would wait that long. It writes its pid to the
// file named by its first argument once its SIGTERM handler is in place, so
// that the test knows when it is up and can end it afterwards.
import { writeFileSync } from "node:fs";

process.on("SIGTERM", () => {});
writeFileSync(process.argv[2], String(process.pid));
setTimeout(() => {}, 20_000);
