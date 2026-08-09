import {
  createEntireAdapter,
  type CommandRunner as EntireCommandRunner,
  type ProviderCapabilityReport,
  type WorkCaptureProviderAdapter,
} from "../../../packages/adapters/entire/src/index.js";
import type {
  CaptureProvider,
  CaptureProviderStatus,
  CommandRunner,
} from "../../../packages/core/src/index.js";

function status(
  state: CaptureProviderStatus["state"],
  message: string,
): CaptureProviderStatus {
  return {
    schema_version: 1,
    provider: "entire",
    state,
    capture_ready: state === "ready",
    message,
  };
}

function normalizeInspection(
  report: ProviderCapabilityReport,
): CaptureProviderStatus {
  if (!report.installation.installed) {
    return status("unavailable", "Entire is not installed or is not on PATH.");
  }
  if (!report.installation.supported) {
    if (report.installation.version === null) {
      return status(
        "invalid_output",
        "The installed Entire version could not be identified.",
      );
    }
    return status(
      "unavailable",
      `Entire >=${report.installation.minimumVersion} is required; found ${report.installation.version}.`,
    );
  }
  if (report.repository.enabled === false) {
    return status(
      "disabled",
      "Entire is installed but not enabled for this repository.",
    );
  }
  if (report.repository.enabled === true) {
    return status("ready", "Entire capture is enabled for this repository.");
  }
  if (report.diagnostics.includes("entire_status_unrecognized")) {
    return status(
      "invalid_output",
      "Entire returned an unsupported status payload.",
    );
  }
  return status("error", "Entire status could not be determined safely.");
}

function bridgeCommandRunner(
  commandRunner: CommandRunner,
  defaultCwd: string,
): EntireCommandRunner {
  return async (invocation) => {
    const result = await commandRunner.run({
      command: invocation.command,
      args: invocation.args,
      cwd: invocation.cwd ?? defaultCwd,
    });
    return {
      exitCode: result.exit_code ?? (result.error_code === "ENOENT" ? 127 : 1),
      stdout: result.stdout,
      stderr: result.stderr,
    };
  };
}

export function createEntireProviderAdapter(
  commandRunner: CommandRunner,
  cwd: string,
): WorkCaptureProviderAdapter {
  return createEntireAdapter({
    runner: bridgeCommandRunner(commandRunner, cwd),
  });
}

export function createEntireCaptureProvider(
  commandRunner: CommandRunner,
  cwd: string,
): CaptureProvider {
  const adapter = createEntireProviderAdapter(commandRunner, cwd);
  return {
    id: adapter.providerId,
    async status() {
      return normalizeInspection(await adapter.inspect({ cwd }));
    },
  };
}
