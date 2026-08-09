import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const benchmarkRoot = resolve(repositoryRoot, "benchmarks/handoff-v0");
const manifest = JSON.parse(
  await readFile(resolve(benchmarkRoot, "benchmark.json"), "utf8"),
);

if (
  manifest?.benchmark_id !== "owc-cross-agent-handoff-v0" ||
  manifest?.fixture_version !== "0.1.0" ||
  typeof manifest?.sha256 !== "object" ||
  manifest.sha256 === null
) {
  throw new Error("The benchmark lock manifest is invalid.");
}

const verified = [];
for (const [path, expected] of Object.entries(manifest.sha256).sort()) {
  if (
    typeof expected !== "string" ||
    !/^[a-f0-9]{64}$/.test(expected) ||
    !isSafeRelativePath(path)
  ) {
    throw new Error("The benchmark lock manifest contains an invalid entry.");
  }
  const absolute = resolve(benchmarkRoot, path);
  const beneath = relative(benchmarkRoot, absolute);
  if (beneath !== path) {
    throw new Error("The benchmark lock entry escapes its root.");
  }
  const bytes = await readFile(absolute);
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== expected) {
    throw new Error(`Benchmark fixture digest mismatch: ${path}`);
  }
  verified.push({ path, sha256: actual, byte_length: bytes.byteLength });
}

process.stdout.write(
  `${JSON.stringify(
    {
      schema_version: 1,
      benchmark_id: manifest.benchmark_id,
      fixture_version: manifest.fixture_version,
      ok: true,
      verified,
    },
    null,
    2,
  )}\n`,
);

function isSafeRelativePath(path) {
  return (
    typeof path === "string" &&
    path.length > 0 &&
    !path.startsWith("/") &&
    !path.includes("\\") &&
    !path
      .split("/")
      .some((segment) => segment === "" || segment === "." || segment === "..")
  );
}
