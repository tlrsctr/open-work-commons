import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const result = spawnSync(
  process.execPath,
  ["--test", "benchmarks/handoff-v0/evaluator/acceptance.test.mjs"],
  {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      OWC_BENCHMARK_CANDIDATE: resolve(
        repositoryRoot,
        "benchmarks/handoff-v0/reference",
      ),
    },
    encoding: "utf8",
    timeout: 30_000,
  },
);

if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
if (result.error || result.status !== 0) {
  process.stderr.write("The frozen benchmark reference did not pass.\n");
  process.exitCode = 1;
}
