import { spawn } from "node:child_process";
import { access } from "node:fs/promises";
import type {
  CommandResult,
  CommandRunner,
  FileSystemProbe,
} from "../../../packages/core/src/index.js";

const defaultTimeoutMs = 5_000;
const defaultTerminationGraceMs = 250;
const defaultForcedSettlementMs = 250;
const maxOutputCharacters = 128 * 1024;

function appendBounded(current: string, chunk: Buffer): string {
  if (current.length >= maxOutputCharacters) return current;
  return (current + chunk.toString("utf8")).slice(0, maxOutputCharacters);
}

export function createNodeCommandRunner(
  timeoutMs = defaultTimeoutMs,
  terminationGraceMs = defaultTerminationGraceMs,
  forcedSettlementMs = defaultForcedSettlementMs,
): CommandRunner {
  return {
    run(request) {
      return new Promise<CommandResult>((resolve) => {
        let stdout = "";
        let stderr = "";
        let settled = false;
        let timedOut = false;
        let terminationTimer: NodeJS.Timeout | undefined;
        let forcedSettlementTimer: NodeJS.Timeout | undefined;
        const child = spawn(request.command, [...request.args], {
          cwd: request.cwd,
          env: process.env,
          stdio: ["ignore", "pipe", "pipe"],
        });

        const finish = (result: CommandResult) => {
          if (settled) return;
          settled = true;
          clearTimeout(timeoutTimer);
          if (terminationTimer !== undefined) clearTimeout(terminationTimer);
          if (forcedSettlementTimer !== undefined) {
            clearTimeout(forcedSettlementTimer);
          }
          resolve(result);
        };

        const timeoutResult = (): CommandResult => ({
          exit_code: null,
          stdout,
          stderr,
          error_code: "ETIMEDOUT",
          timed_out: true,
        });

        const signalChild = (signal: NodeJS.Signals): void => {
          try {
            child.kill(signal);
          } catch {
            // The fixed forced-settlement deadline remains authoritative.
          }
        };

        const timeoutTimer = setTimeout(() => {
          timedOut = true;
          signalChild("SIGTERM");
          terminationTimer = setTimeout(() => {
            signalChild("SIGKILL");
            forcedSettlementTimer = setTimeout(() => {
              // A child that cannot emit close must not retain the CLI or its
              // pipes indefinitely after the hard-kill attempt.
              child.stdout.destroy();
              child.stderr.destroy();
              child.unref();
              finish(timeoutResult());
            }, forcedSettlementMs);
          }, terminationGraceMs);
        }, timeoutMs);

        child.stdout.on("data", (chunk: Buffer) => {
          stdout = appendBounded(stdout, chunk);
        });
        child.stderr.on("data", (chunk: Buffer) => {
          stderr = appendBounded(stderr, chunk);
        });
        child.on("error", (error: NodeJS.ErrnoException) => {
          if (timedOut) {
            finish(timeoutResult());
            return;
          }
          finish({
            exit_code: null,
            stdout,
            stderr,
            ...(error.code ? { error_code: error.code } : {}),
          });
        });
        child.on("close", (exitCode) => {
          if (timedOut) {
            finish(timeoutResult());
            return;
          }
          finish({
            exit_code: exitCode,
            stdout,
            stderr,
          });
        });
      });
    },
  };
}

export const nodeFileSystemProbe: FileSystemProbe = {
  async can_access(path) {
    try {
      await access(path);
      return true;
    } catch {
      return false;
    }
  },
};
