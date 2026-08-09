#!/usr/bin/env node

import { writeFileSync } from "node:fs";
import { join } from "node:path";

const signalMarker = join(process.cwd(), "sigterm-observed");
const pidMarker = join(process.cwd(), "probe-pid");

writeFileSync(pidMarker, `${process.pid}\n`, { flag: "wx", mode: 0o600 });
process.stdout.write("Entire CLI 0.9.0\nprivate-timeout-stdout\n");
process.stderr.write("private-timeout-stderr\n");

process.once("SIGTERM", () => {
  writeFileSync(signalMarker, "observed\n", { flag: "wx", mode: 0o600 });
});

setInterval(() => undefined, 1_000);
