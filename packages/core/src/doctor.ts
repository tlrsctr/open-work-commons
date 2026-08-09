import type {
  CaptureProvider,
  CaptureProviderStatus,
} from "./capture-provider.js";
import { providerStatusExitCode } from "./capture-provider.js";
import {
  ExitCode,
  highestPriorityExitCode,
  type ExitCodeValue,
} from "./exit-codes.js";
import type { CommandRunner, FileSystemProbe } from "./runtime.js";

export type DoctorCheck = {
  id: string;
  status: "pass" | "fail";
  message: string;
  exit_code: ExitCodeValue;
};

export type DoctorReport = {
  schema_version: 1;
  ok: boolean;
  exit_code: ExitCodeValue;
  checks: DoctorCheck[];
  providers: CaptureProviderStatus[];
};

export type DoctorDependencies = {
  cwd: string;
  node_version: string;
  file_system: FileSystemProbe;
  command_runner: CommandRunner;
  providers: readonly CaptureProvider[];
};

function nodeMajor(version: string): number | null {
  const match = /^v?(\d+)(?:\.|$)/.exec(version);
  return match ? Number(match[1]) : null;
}

function passingCheck(id: string, message: string): DoctorCheck {
  return { id, status: "pass", message, exit_code: ExitCode.success };
}

function failingCheck(
  id: string,
  message: string,
  exitCode: ExitCodeValue,
): DoctorCheck {
  return { id, status: "fail", message, exit_code: exitCode };
}

export async function runDoctor(
  dependencies: DoctorDependencies,
): Promise<DoctorReport> {
  const checks: DoctorCheck[] = [];
  const major = nodeMajor(dependencies.node_version);
  checks.push(
    major !== null && major >= 22
      ? passingCheck(
          "runtime.node",
          `Node ${dependencies.node_version} is supported.`,
        )
      : failingCheck(
          "runtime.node",
          `Node >=22 is required; found ${dependencies.node_version}.`,
          ExitCode.notReady,
        ),
  );

  const cwdAccessible = await dependencies.file_system.can_access(
    dependencies.cwd,
  );
  checks.push(
    cwdAccessible
      ? passingCheck("filesystem.cwd", "The working directory is accessible.")
      : failingCheck(
          "filesystem.cwd",
          "The working directory is not accessible.",
          ExitCode.notReady,
        ),
  );

  const gitVersion = await dependencies.command_runner.run({
    command: "git",
    args: ["--version"],
    cwd: dependencies.cwd,
  });
  const gitUnavailable = gitVersion.error_code === "ENOENT";
  checks.push(
    gitVersion.exit_code === 0
      ? passingCheck("dependency.git", "Git is available.")
      : failingCheck(
          "dependency.git",
          gitUnavailable
            ? "Git is not installed."
            : "Git could not be executed.",
          gitUnavailable
            ? ExitCode.dependencyUnavailable
            : ExitCode.providerFailure,
        ),
  );

  if (gitVersion.exit_code === 0) {
    const gitRepository = await dependencies.command_runner.run({
      command: "git",
      args: ["rev-parse", "--show-toplevel"],
      cwd: dependencies.cwd,
    });
    checks.push(
      gitRepository.exit_code === 0
        ? passingCheck(
            "git.repository",
            "The working directory is in a Git repository.",
          )
        : failingCheck(
            "git.repository",
            "The working directory is not in a readable Git repository.",
            ExitCode.notReady,
          ),
    );
  } else {
    checks.push(
      failingCheck(
        "git.repository",
        "Git repository detection was skipped because Git is unavailable.",
        gitUnavailable
          ? ExitCode.dependencyUnavailable
          : ExitCode.providerFailure,
      ),
    );
  }

  const providers: CaptureProviderStatus[] = [];
  for (const provider of dependencies.providers) {
    const status = await provider.status();
    providers.push(status);
    checks.push({
      id: `provider.${provider.id}`,
      status: status.capture_ready ? "pass" : "fail",
      message: status.message,
      exit_code: providerStatusExitCode(status),
    });
  }

  const exitCode = highestPriorityExitCode(
    checks.map((check) => check.exit_code),
  );
  return {
    schema_version: 1,
    ok: exitCode === ExitCode.success,
    exit_code: exitCode,
    checks,
    providers,
  };
}
