import type {
  CommandRunner,
  ExitCodeValue,
  FileSystemProbe,
} from "../../../packages/core/src/index.js";
import {
  ExitCode,
  providerStatusExitCode,
  runDoctor,
} from "../../../packages/core/src/index.js";
import {
  sha256,
  verifyLogicalArchive,
  type ArchiveVerificationResult,
  type ExternalRepositoryVerification,
} from "../../../packages/archive/src/index.js";
import {
  GitStateCaptureError,
  type CapturedGitState,
  type GitStateArtifact,
} from "../../../packages/git-state/src/index.js";
import {
  DeviceIdentityError,
  type DeviceSigningIdentity,
  type DeviceIdentityErrorCode,
  type PublicDeviceIdentity,
} from "../../../packages/identity/src/index.js";
import {
  HandoffError,
  inspectHandoff,
  type HandoffInspection,
  type OperatorHandoffPlan,
} from "../../../packages/handoff/src/index.js";
import {
  compileResumeBundle,
  ResumeCompileError,
  type ResumeTarget,
} from "../../../packages/resume/src/index.js";
import type { ArchiveLoader } from "./archive-directory.js";
import { readVerifiedRootGitState } from "./archive-repository.js";
import {
  createEntireCaptureProvider,
  createEntireProviderAdapter,
} from "./entire-provider.js";
import type { DeviceIdentityRuntime } from "./device-identity-runtime.js";
import type { GitStateRuntime } from "./git-state-runtime.js";
import {
  HandoffFileError,
  type HandoffFileRuntime,
} from "./handoff-file-runtime.js";
import type { WorkspaceStoreRuntime } from "./store-runtime.js";

export type OutputSink = {
  write(value: string): void;
};

export interface CliClock {
  now(): Date;
}

export type CliDependencies = {
  cwd: string;
  node_version: string;
  file_system: FileSystemProbe;
  command_runner: CommandRunner;
  archive_loader: ArchiveLoader;
  device_identity: DeviceIdentityRuntime;
  git_state: GitStateRuntime;
  handoff_files: HandoffFileRuntime;
  workspace_store: WorkspaceStoreRuntime;
  clock: CliClock;
  stdout: OutputSink;
  stderr: OutputSink;
};

type OutputMode = "text" | "json";

const usage = [
  "Usage:",
  "  owc init [--json]",
  "  owc store health [--json]",
  "  owc identity status [--json]",
  "  owc doctor [--json]",
  "  owc provider entire status [--json]",
  "  owc provider entire checkpoints [--json]",
  "  owc archive verify <directory> (--trust=<sha256:fingerprint> | --allow-untrusted-signer) [--repo=<directory>] [--json]",
  "  owc git snapshot [--captured-at=<RFC3339>] [--repository-id=<id>] [--include-untracked] [--json]",
  "  owc handoff inspect --plan=<file> --entire-detail=<file> --captured-at=<RFC3339> [--include-untracked] [--json]",
  "  owc handoff create --plan=<file> --entire-detail=<file> --captured-at=<RFC3339> --approve=<sha256:digest> --output=<new-directory> [--include-untracked] [--json]",
  "  owc resume compile <archive-directory> --target=<codex|claude> --max-items=<N> --max-bytes=<N> (--trust=<sha256:fingerprint> | --allow-untrusted-signer) [--json]",
].join("\n");

function writeJson(sink: OutputSink, value: unknown): void {
  sink.write(`${JSON.stringify(value, null, 2)}\n`);
}

function writeUsageError(
  dependencies: CliDependencies,
  outputMode: OutputMode,
  message: string,
): ExitCodeValue {
  if (outputMode === "json") {
    writeJson(dependencies.stdout, {
      schema_version: 1,
      command: "usage",
      ok: false,
      exit_code: ExitCode.usage,
      error: { code: "usage", message },
      usage: usage.split("\n"),
    });
  } else {
    dependencies.stderr.write(`${message}\n${usage}\n`);
  }
  return ExitCode.usage;
}

function parseArguments(argv: readonly string[]):
  | {
      mode: OutputMode;
      command: string[];
    }
  | { error: string; mode: OutputMode } {
  const jsonFlags = argv.filter((argument) => argument === "--json").length;
  const mode: OutputMode = jsonFlags >= 1 ? "json" : "text";
  if (jsonFlags > 1)
    return { error: "--json may be specified only once.", mode };
  return { mode, command: argv.filter((argument) => argument !== "--json") };
}

interface ScopedOptions {
  readonly positionals: readonly string[];
  readonly values: ReadonlyMap<string, string>;
  readonly booleans: ReadonlySet<string>;
}

function parseScopedOptions(
  args: readonly string[],
  valueOptions: readonly string[],
  booleanOptions: readonly string[] = [],
): ScopedOptions | { error: string } {
  const allowedValues = new Set(valueOptions);
  const allowedBooleans = new Set(booleanOptions);
  const values = new Map<string, string>();
  const booleans = new Set<string>();
  const positionals: string[] = [];

  for (const argument of args) {
    if (!argument.startsWith("-")) {
      positionals.push(argument);
      continue;
    }
    if (allowedBooleans.has(argument)) {
      if (booleans.has(argument)) {
        return { error: `${argument} may be specified only once.` };
      }
      booleans.add(argument);
      continue;
    }
    const equals = argument.indexOf("=");
    const name = equals < 0 ? argument : argument.slice(0, equals);
    if (allowedValues.has(name)) {
      if (equals < 0) {
        return { error: `${name} requires a value using ${name}=<value>.` };
      }
      if (values.has(name)) {
        return { error: `${name} may be specified only once.` };
      }
      const value = argument.slice(equals + 1);
      if (value.length === 0) return { error: `${name} requires a value.` };
      values.set(name, value);
      continue;
    }
    return { error: `Unknown option: ${argument}` };
  }

  return { positionals, values, booleans };
}

function parseTrustFingerprint(
  value: string | undefined,
): string | null | { error: string } {
  if (value === undefined) return null;
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) {
    return {
      error:
        "--trust requires a sha256 fingerprint with 64 lowercase hexadecimal characters.",
    };
  }
  return value;
}

function parseSignerPolicy(options: ScopedOptions):
  | {
      trustedSignerFingerprint: string | null;
      integrityOnlyAcknowledged: boolean;
    }
  | { error: string } {
  const trust = parseTrustFingerprint(options.values.get("--trust"));
  if (trust !== null && typeof trust === "object") return trust;
  const integrityOnlyAcknowledged = options.booleans.has(
    "--allow-untrusted-signer",
  );
  if (trust !== null && integrityOnlyAcknowledged) {
    return {
      error: "--trust and --allow-untrusted-signer are mutually exclusive.",
    };
  }
  if (trust === null && !integrityOnlyAcknowledged) {
    return {
      error:
        "Signer policy is required: pass --trust=<fingerprint> or explicitly acknowledge integrity-only verification with --allow-untrusted-signer.",
    };
  }
  return {
    trustedSignerFingerprint: trust,
    integrityOnlyAcknowledged,
  };
}

function parsePositiveInteger(
  option: string,
  value: string | undefined,
): number | { error: string } {
  if (value === undefined) return { error: `${option} is required.` };
  if (!/^[1-9][0-9]*$/.test(value)) {
    return { error: `${option} must be a positive integer.` };
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    return { error: `${option} must be a positive safe integer.` };
  }
  return parsed;
}

function isRfc3339Timestamp(value: string): boolean {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(
      value,
    );
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = Number(match[7] ?? 0);
  const offsetMinute = Number(match[8] ?? 0);
  const daysInMonth = [
    31,
    year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ][month - 1];
  return (
    daysInMonth !== undefined &&
    day >= 1 &&
    day <= daysInMonth &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59 &&
    offsetHour <= 23 &&
    offsetMinute <= 59
  );
}

function isValidRepositoryId(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 512 &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function renderDoctorText(
  dependencies: CliDependencies,
  report: Awaited<ReturnType<typeof runDoctor>>,
): void {
  for (const check of report.checks) {
    dependencies.stdout.write(
      `${check.status === "pass" ? "PASS" : "FAIL"} ${check.id}: ${check.message}\n`,
    );
  }
  dependencies.stdout.write(
    `Doctor: ${report.ok ? "ready" : "not ready"} (exit ${report.exit_code})\n`,
  );
}

function renderArchiveVerificationText(
  dependencies: CliDependencies,
  report: ArchiveVerificationResult,
): void {
  dependencies.stdout.write(
    `Archive integrity: ${report.integrity.valid ? "valid" : "invalid"}\n`,
  );
  dependencies.stdout.write(
    `Signer: signature=${report.signer.signatureValid ? "valid" : "invalid"} trust=${report.signer.trust} fingerprint=${report.signer.fingerprint ?? "unavailable"}\n`,
  );
  for (const issue of report.integrity.issues) {
    dependencies.stdout.write(
      `FAIL ${issue.code} at ${issue.location}: ${issue.message}\n`,
    );
  }
  const external = report.externalRepositoryVerification;
  dependencies.stdout.write(
    `External repository: ${external.status}${"reason" in external ? ` (${external.reason})` : ""}\n`,
  );
}

function artifactMetadata(artifact: GitStateArtifact): {
  path: string;
  media_type: string;
  digest: string;
  byte_length: number;
} {
  return {
    path: artifact.path,
    media_type: artifact.mediaType,
    digest: artifact.digest,
    byte_length: artifact.byteLength,
  };
}

function gitSnapshotData(
  captured: CapturedGitState,
  includeUntracked: boolean,
) {
  return {
    state: captured.state,
    state_serialization: {
      digest: captured.stateDigest,
      byte_length: captured.stateBytes.byteLength,
    },
    artifacts: {
      tracked_patch:
        captured.patchArtifact === null
          ? null
          : artifactMetadata(captured.patchArtifact),
      untracked: captured.untrackedArtifacts.map(artifactMetadata),
    },
    capture_policy: {
      untracked: includeUntracked ? "include" : "manifest-only",
      artifact_bytes_emitted: false,
      archive_created: false,
    },
  };
}

function renderGitSnapshotText(
  dependencies: CliDependencies,
  captured: CapturedGitState,
  includeUntracked: boolean,
): void {
  const state = captured.state;
  dependencies.stdout.write(
    `Repository: ${state.repository_id}\nBase: ${state.base_commit}\nHead: ${state.head_commit}\nTree: ${state.head_tree}\nWorktree: ${state.worktree.clean ? "clean" : "changed"}\n`,
  );
  dependencies.stdout.write(
    `State: ${captured.stateDigest} (${captured.stateBytes.byteLength} bytes)\n`,
  );
  if (captured.patchArtifact === null) {
    dependencies.stdout.write("Tracked patch: none\n");
  } else {
    dependencies.stdout.write(
      `Tracked patch: ${captured.patchArtifact.path} ${captured.patchArtifact.digest} (${captured.patchArtifact.byteLength} bytes)\n`,
    );
  }
  dependencies.stdout.write(
    `Untracked: ${state.worktree.untracked.length} manifest entries; ${captured.untrackedArtifacts.length} content artifacts ${includeUntracked ? "captured in memory" : "captured (manifest-only policy)"}.\n`,
  );
  dependencies.stdout.write(
    "Artifact bytes were not emitted, and no archive was created.\n",
  );
}

function writeFixedError(
  dependencies: CliDependencies,
  mode: OutputMode,
  command: string,
  exitCode: ExitCodeValue,
  code: string,
  message: string,
): ExitCodeValue {
  if (mode === "json") {
    writeJson(dependencies.stdout, {
      schema_version: 1,
      command,
      ok: false,
      exit_code: exitCode,
      error: { code, message },
    });
  } else {
    dependencies.stderr.write(`${message}\n`);
  }
  return exitCode;
}

function publicIdentityOutput(identity: PublicDeviceIdentity) {
  return {
    format: identity.format,
    schema_version: identity.schema_version,
    algorithm: identity.algorithm,
    key_id: identity.key_id,
    fingerprint: identity.fingerprint,
    public_key: identity.public_key,
    public_key_spki: identity.public_key_spki,
  };
}

function identityExitCode(code: DeviceIdentityErrorCode): ExitCodeValue {
  if (code === "unsupported_platform") return ExitCode.dependencyUnavailable;
  if (code === "not_found" || code === "identity_busy") {
    return ExitCode.notReady;
  }
  return ExitCode.storeInvalid;
}

function identityMessage(code: DeviceIdentityErrorCode): string {
  switch (code) {
    case "not_found":
      return "The local device identity is not initialized.";
    case "unsupported_platform":
      return "The local device identity storage adapter is unavailable on this platform.";
    case "identity_busy":
      return "Another local device identity operation is in progress.";
    case "unsafe_storage":
    case "unsafe_permissions":
    case "integrity_failure":
      return "The local device identity failed its storage safety checks.";
    case "signing_failure":
      return "The local device identity signing capability is unavailable.";
  }
}

function writeIdentityFailure(
  dependencies: CliDependencies,
  mode: OutputMode,
  command: "init" | "identity status",
  code: DeviceIdentityErrorCode,
  storeInitialized: boolean,
): ExitCodeValue {
  const exitCode = identityExitCode(code);
  const message = identityMessage(code);
  if (mode === "json") {
    writeJson(dependencies.stdout, {
      schema_version: 1,
      command,
      ok: false,
      exit_code: exitCode,
      error: { code: `identity_${code}`, message },
      ...(storeInitialized
        ? {
            data: {
              workspace_store_initialized: true,
              identity_ready: false,
              init_retry_safe: true,
            },
          }
        : {}),
    });
  } else {
    dependencies.stderr.write(`${message}\n`);
    if (storeInitialized) {
      dependencies.stderr.write(
        "The workspace store remains initialized; retrying owc init is safe.\n",
      );
    }
  }
  return exitCode;
}

function gitCaptureFailure(
  dependencies: CliDependencies,
  mode: OutputMode,
  error: GitStateCaptureError,
  command = "git snapshot",
): ExitCodeValue {
  if (error.code === "INVALID_CAPTURE_TIME" || error.code === "INVALID_INPUT") {
    return writeUsageError(
      dependencies,
      mode,
      "The Git snapshot options are invalid.",
    );
  }
  if (error.code === "SUBPROCESS_ERROR") {
    return writeFixedError(
      dependencies,
      mode,
      command,
      ExitCode.dependencyUnavailable,
      "git_unavailable",
      "Git could not be invoked safely for this snapshot.",
    );
  }
  return writeFixedError(
    dependencies,
    mode,
    command,
    ExitCode.notReady,
    "git_state_not_capturable",
    "The repository state cannot be captured exactly by the v0 boundary.",
  );
}

interface ParsedHandoffCommand {
  readonly planPath: string;
  readonly entireDetailPath: string;
  readonly capturedAt: string;
  readonly includeUntracked: boolean;
  readonly approvalDigest?: `sha256:${string}`;
  readonly outputPath?: string;
}

function parseHandoffCommand(
  args: readonly string[],
  creating: boolean,
): ParsedHandoffCommand | { error: string } {
  const valueOptions = ["--plan", "--entire-detail", "--captured-at"];
  if (creating) valueOptions.push("--approve", "--output");
  const options = parseScopedOptions(args, valueOptions, [
    "--include-untracked",
  ]);
  if ("error" in options) return options;
  if (options.positionals.length !== 0) {
    return {
      error: `handoff ${creating ? "create" : "inspect"} does not accept positional arguments.`,
    };
  }
  const planPath = options.values.get("--plan");
  const entireDetailPath = options.values.get("--entire-detail");
  const capturedAt = options.values.get("--captured-at");
  if (planPath === undefined) return { error: "--plan is required." };
  if (entireDetailPath === undefined) {
    return { error: "--entire-detail is required." };
  }
  if (capturedAt === undefined) {
    return { error: "--captured-at is required." };
  }
  if (!isRfc3339Timestamp(capturedAt)) {
    return { error: "--captured-at must be a real RFC 3339 timestamp." };
  }
  const result: ParsedHandoffCommand = {
    planPath,
    entireDetailPath,
    capturedAt,
    includeUntracked: options.booleans.has("--include-untracked"),
  };
  if (!creating) return result;

  const approval = options.values.get("--approve");
  if (approval === undefined) return { error: "--approve is required." };
  if (!/^sha256:[a-f0-9]{64}$/.test(approval)) {
    return {
      error:
        "--approve requires a sha256 digest with 64 lowercase hexadecimal characters.",
    };
  }
  const outputPath = options.values.get("--output");
  if (outputPath === undefined) return { error: "--output is required." };
  return {
    ...result,
    approvalDigest: approval as `sha256:${string}`,
    outputPath,
  };
}

function inspectionOnlyIdentity(
  publicIdentity: PublicDeviceIdentity,
): DeviceSigningIdentity {
  return {
    publicIdentity,
    sign(_payload) {
      throw new Error("inspection_must_not_sign");
    },
    createSignedArchive(_input) {
      throw new Error("inspection_must_not_sign");
    },
  };
}

function handoffIdentityFailure(
  dependencies: CliDependencies,
  mode: OutputMode,
  command: "handoff inspect" | "handoff create",
  code: DeviceIdentityErrorCode,
): ExitCodeValue {
  return writeFixedError(
    dependencies,
    mode,
    command,
    identityExitCode(code),
    `identity_${code}`,
    code === "not_found"
      ? "Run owc init before creating a portable handoff."
      : identityMessage(code),
  );
}

function handoffFileFailure(
  dependencies: CliDependencies,
  mode: OutputMode,
  command: "handoff inspect" | "handoff create",
  error: HandoffFileError,
): ExitCodeValue {
  const mapping: Record<
    HandoffFileError["code"],
    { exitCode: ExitCodeValue; message: string }
  > = {
    input_unavailable: {
      exitCode: ExitCode.notReady,
      message: "A handoff input file could not be read safely.",
    },
    input_resource_limit: {
      exitCode: ExitCode.notReady,
      message: "A handoff input file exceeds the v0 resource limit.",
    },
    plan_invalid: {
      exitCode: ExitCode.notReady,
      message: "The operator handoff plan is not valid bounded JSON.",
    },
    output_exists: {
      exitCode: ExitCode.notReady,
      message: "The archive output must be a new directory.",
    },
    output_unsafe: {
      exitCode: ExitCode.notReady,
      message: "The archive output location could not be resolved safely.",
    },
    archive_invalid: {
      exitCode: ExitCode.archiveInvalid,
      message: "The approved archive failed publication safety checks.",
    },
    archive_publish_failed: {
      exitCode: ExitCode.archiveInvalid,
      message: "The approved archive could not be published atomically.",
    },
  };
  const selected = mapping[error.code];
  return writeFixedError(
    dependencies,
    mode,
    command,
    selected.exitCode,
    `handoff_${error.code}`,
    selected.message,
  );
}

function handoffCoreFailure(
  dependencies: CliDependencies,
  mode: OutputMode,
  command: "handoff inspect" | "handoff create",
  error: HandoffError,
): ExitCodeValue {
  const providerCodes = new Set([
    "entire_import_invalid",
    "provider_mismatch",
    "external_checkpoint_mismatch",
    "blocking_import_gap",
  ]);
  const exitCode =
    error.code === "archive_construction_failed"
      ? ExitCode.archiveInvalid
      : error.code === "store_plan_invalid" ||
          error.code === "signing_identity_invalid"
        ? ExitCode.storeInvalid
        : providerCodes.has(error.code)
          ? ExitCode.invalidProviderOutput
          : ExitCode.notReady;
  const messages: Record<HandoffError["code"], string> = {
    invalid_input: "The handoff inputs do not satisfy the v0 boundary.",
    invalid_plan: "The operator handoff plan does not satisfy the v0 boundary.",
    entire_import_invalid:
      "The supplied Entire checkpoint detail is not a valid bounded Entire 0.9 payload.",
    provider_mismatch:
      "The operator plan and supplied checkpoint provider do not match.",
    external_checkpoint_mismatch:
      "The operator plan and supplied external checkpoint identifier do not match.",
    blocking_import_gap:
      "The supplied checkpoint metadata has a blocking import gap.",
    git_state_invalid:
      "The exact Git state could not be bound to this handoff.",
    signing_identity_invalid:
      "The existing device signing identity is not valid for this handoff.",
    approval_mismatch:
      "The supplied approval digest does not match the recomputed handoff review.",
    archive_construction_failed:
      "The exact approved archive could not be signed and verified.",
    store_plan_invalid:
      "The approved handoff could not produce an exact local-store plan.",
  };
  return writeFixedError(
    dependencies,
    mode,
    command,
    exitCode,
    `handoff_${error.code}`,
    messages[error.code],
  );
}

function renderHandoffInspectionText(
  dependencies: CliDependencies,
  inspection: HandoffInspection,
): void {
  dependencies.stdout.write(
    `Approval digest: ${inspection.approvalDigest}\nArchive: ${inspection.identifiers.archiveId}\nCheckpoint: ${inspection.identifiers.checkpointId}\nSigner: ${inspection.signer.fingerprint}\n`,
  );
  dependencies.stdout.write(
    `Review: ${inspection.included.events.length} events, ${inspection.included.artifacts.length} Git artifacts, ${inspection.proposedArchive.entries.length} archive entries, ${inspection.proposedArchive.limits.expandedBytes} expanded bytes.\n`,
  );
  dependencies.stdout.write(
    `Excluded by default: ${inspection.excluded.map((item) => item.category).join(", ")}.\n`,
  );
  dependencies.stdout.write(
    "No signing, persistence, archive publication, or provider checkpoint command occurred.\n",
  );
}

export async function runCli(
  argv: readonly string[],
  dependencies: CliDependencies,
): Promise<ExitCodeValue> {
  const parsed = parseArguments(argv);
  if ("error" in parsed) {
    return writeUsageError(dependencies, parsed.mode, parsed.error);
  }
  const { command, mode } = parsed;
  if (
    command.length === 0 ||
    (command.length === 1 &&
      ["help", "--help", "-h"].includes(command[0] ?? ""))
  ) {
    if (mode === "json") {
      writeJson(dependencies.stdout, {
        schema_version: 1,
        command: "help",
        ok: true,
        exit_code: ExitCode.success,
        usage: usage.split("\n"),
      });
    } else {
      dependencies.stdout.write(`${usage}\n`);
    }
    return ExitCode.success;
  }

  try {
    const entireProvider = createEntireCaptureProvider(
      dependencies.command_runner,
      dependencies.cwd,
    );
    const entireAdapter = createEntireProviderAdapter(
      dependencies.command_runner,
      dependencies.cwd,
    );
    if (command.length === 1 && command[0] === "init") {
      let initialized: { store_path: string };
      try {
        initialized = await dependencies.workspace_store.initialize(
          dependencies.cwd,
        );
      } catch {
        if (mode === "json") {
          writeJson(dependencies.stdout, {
            schema_version: 1,
            command: "init",
            ok: false,
            exit_code: ExitCode.storeInvalid,
            error: {
              code: "store_initialization_failed",
              message: "The private OWC store could not be initialized safely.",
            },
          });
        } else {
          dependencies.stderr.write(
            "The private OWC store could not be initialized safely.\n",
          );
        }
        return ExitCode.storeInvalid;
      }

      let identity: PublicDeviceIdentity;
      try {
        identity = await dependencies.device_identity.openOrCreate(
          initialized.store_path,
        );
      } catch (error) {
        const code =
          error instanceof DeviceIdentityError
            ? error.code
            : "integrity_failure";
        return writeIdentityFailure(dependencies, mode, "init", code, true);
      }

      if (mode === "json") {
        writeJson(dependencies.stdout, {
          schema_version: 1,
          command: "init",
          ok: true,
          exit_code: ExitCode.success,
          data: {
            initialized: true,
            workspace_store: {
              initialized: true,
              content_policy: "deny-until-configured",
            },
            identity: publicIdentityOutput(identity),
          },
        });
      } else {
        dependencies.stdout.write(
          `Initialized the private OWC store and device identity. Identity fingerprint: ${identity.fingerprint}. Content access remains denied until a policy is configured.\n`,
        );
      }
      return ExitCode.success;
    }

    if (
      command.length === 2 &&
      command[0] === "store" &&
      command[1] === "health"
    ) {
      try {
        const health = await dependencies.workspace_store.health(
          dependencies.cwd,
        );
        const exitCode = health.ok ? ExitCode.success : ExitCode.storeInvalid;
        if (mode === "json") {
          writeJson(dependencies.stdout, {
            schema_version: 1,
            command: "store health",
            ok: health.ok,
            exit_code: exitCode,
            data: health,
          });
        } else {
          dependencies.stdout.write(
            `Store health: ${health.ok ? "healthy" : "invalid"}; events=${health.checkedEvents}; blobs=${health.checkedBlobs}\n`,
          );
          for (const issue of health.issues) {
            dependencies.stdout.write(
              `FAIL ${issue.code} at ${issue.location}: ${issue.message}\n`,
            );
          }
        }
        return exitCode;
      } catch {
        if (mode === "json") {
          writeJson(dependencies.stdout, {
            schema_version: 1,
            command: "store health",
            ok: false,
            exit_code: ExitCode.storeInvalid,
            error: {
              code: "store_unavailable",
              message: "The private OWC store could not be opened safely.",
            },
          });
        } else {
          dependencies.stderr.write(
            "The private OWC store could not be opened safely.\n",
          );
        }
        return ExitCode.storeInvalid;
      }
    }

    if (
      command.length === 2 &&
      command[0] === "identity" &&
      command[1] === "status"
    ) {
      let diagnostic;
      try {
        diagnostic = await dependencies.device_identity.diagnose();
      } catch {
        return writeIdentityFailure(
          dependencies,
          mode,
          "identity status",
          "integrity_failure",
          false,
        );
      }
      if (!diagnostic.ok) {
        return writeIdentityFailure(
          dependencies,
          mode,
          "identity status",
          diagnostic.code,
          false,
        );
      }
      if (mode === "json") {
        writeJson(dependencies.stdout, {
          schema_version: 1,
          command: "identity status",
          ok: true,
          exit_code: ExitCode.success,
          data: {
            state: "ready",
            identity: publicIdentityOutput(diagnostic.identity),
          },
        });
      } else {
        dependencies.stdout.write(
          `Device identity: ready; fingerprint=${diagnostic.identity.fingerprint}; key_id=${diagnostic.identity.key_id}\n`,
        );
      }
      return ExitCode.success;
    }

    if (command.length === 1 && command[0] === "doctor") {
      const report = await runDoctor({
        cwd: dependencies.cwd,
        node_version: dependencies.node_version,
        file_system: dependencies.file_system,
        command_runner: dependencies.command_runner,
        providers: [entireProvider],
      });
      if (mode === "json") {
        writeJson(dependencies.stdout, {
          schema_version: 1,
          command: "doctor",
          ok: report.ok,
          exit_code: report.exit_code,
          data: report,
        });
      } else {
        renderDoctorText(dependencies, report);
      }
      return report.exit_code;
    }

    if (
      command.length === 3 &&
      command[0] === "provider" &&
      command[2] === "status"
    ) {
      if (command[1] !== "entire") {
        return writeUsageError(
          dependencies,
          mode,
          `Unknown provider: ${command[1] ?? ""}`,
        );
      }
      const providerStatus = await entireProvider.status();
      const exitCode = providerStatusExitCode(providerStatus);
      if (mode === "json") {
        writeJson(dependencies.stdout, {
          schema_version: 1,
          command: "provider entire status",
          ok: providerStatus.capture_ready,
          exit_code: exitCode,
          data: providerStatus,
        });
      } else {
        dependencies.stdout.write(
          `Entire: ${providerStatus.state} — ${providerStatus.message}\n`,
        );
      }
      return exitCode;
    }

    if (
      command.length === 3 &&
      command[0] === "provider" &&
      command[1] === "entire" &&
      command[2] === "checkpoints"
    ) {
      const discovery = await entireAdapter.discoverCheckpoints({
        cwd: dependencies.cwd,
      });
      const exitCode =
        discovery.reason === "entire_not_installed" ||
        discovery.reason === "entire_version_unsupported"
          ? ExitCode.dependencyUnavailable
          : ExitCode.notReady;
      if (mode === "json") {
        writeJson(dependencies.stdout, {
          schema_version: 1,
          command: "provider entire checkpoints",
          ok: false,
          exit_code: exitCode,
          data: discovery,
        });
      } else {
        dependencies.stdout.write(
          `Entire checkpoints: unavailable — ${discovery.reason}\n`,
        );
      }
      return exitCode;
    }

    if (command[0] === "git" && command[1] === "snapshot") {
      const options = parseScopedOptions(
        command.slice(2),
        ["--captured-at", "--repository-id"],
        ["--include-untracked"],
      );
      if ("error" in options) {
        return writeUsageError(dependencies, mode, options.error);
      }
      if (options.positionals.length !== 0) {
        return writeUsageError(
          dependencies,
          mode,
          "git snapshot does not accept positional arguments.",
        );
      }
      const suppliedCapturedAt = options.values.get("--captured-at");
      const capturedAt =
        suppliedCapturedAt ??
        (() => {
          const clockValue = dependencies.clock.now();
          return Number.isNaN(clockValue.getTime())
            ? ""
            : clockValue.toISOString();
        })();
      if (!isRfc3339Timestamp(capturedAt)) {
        return writeUsageError(
          dependencies,
          mode,
          "--captured-at must be a real RFC 3339 timestamp.",
        );
      }
      const repositoryId = options.values.get("--repository-id");
      if (repositoryId !== undefined && !isValidRepositoryId(repositoryId)) {
        return writeUsageError(
          dependencies,
          mode,
          "--repository-id must be a non-empty identifier without control characters.",
        );
      }
      const includeUntracked = options.booleans.has("--include-untracked");
      let captured: CapturedGitState;
      try {
        captured = await dependencies.git_state.capture({
          cwd: dependencies.cwd,
          capturedAt,
          ...(repositoryId === undefined ? {} : { repositoryId }),
          includeUntracked,
        });
      } catch (error) {
        if (error instanceof GitStateCaptureError) {
          return gitCaptureFailure(dependencies, mode, error);
        }
        throw error;
      }

      if (mode === "json") {
        writeJson(dependencies.stdout, {
          schema_version: 1,
          command: "git snapshot",
          ok: true,
          exit_code: ExitCode.success,
          data: gitSnapshotData(captured, includeUntracked),
        });
      } else {
        renderGitSnapshotText(dependencies, captured, includeUntracked);
      }
      return ExitCode.success;
    }

    if (
      command[0] === "handoff" &&
      (command[1] === "inspect" || command[1] === "create")
    ) {
      const action = command[1];
      const commandName = `handoff ${action}` as const;
      const creating = action === "create";
      const options = parseHandoffCommand(command.slice(2), creating);
      if ("error" in options) {
        return writeUsageError(dependencies, mode, options.error);
      }

      if (creating) {
        try {
          await dependencies.handoff_files.assertOutputAvailable(
            options.outputPath ?? "",
          );
        } catch (error) {
          if (error instanceof HandoffFileError) {
            return handoffFileFailure(
              dependencies,
              mode,
              "handoff create",
              error,
            );
          }
          throw error;
        }
      }

      let plan: OperatorHandoffPlan;
      let entireCheckpointDetailJson: string;
      try {
        [plan, entireCheckpointDetailJson] = await Promise.all([
          dependencies.handoff_files.readPlan(options.planPath),
          dependencies.handoff_files.readEntireCheckpointDetail(
            options.entireDetailPath,
          ),
        ]);
      } catch (error) {
        if (error instanceof HandoffFileError) {
          return handoffFileFailure(dependencies, mode, commandName, error);
        }
        throw error;
      }

      let diagnostic;
      try {
        diagnostic = await dependencies.device_identity.diagnose();
      } catch {
        return handoffIdentityFailure(
          dependencies,
          mode,
          commandName,
          "integrity_failure",
        );
      }
      if (!diagnostic.ok) {
        return handoffIdentityFailure(
          dependencies,
          mode,
          commandName,
          diagnostic.code,
        );
      }

      let git: CapturedGitState;
      try {
        git = await dependencies.git_state.capture({
          cwd: dependencies.cwd,
          capturedAt: options.capturedAt,
          includeUntracked: options.includeUntracked,
        });
      } catch (error) {
        if (error instanceof GitStateCaptureError) {
          return gitCaptureFailure(dependencies, mode, error, commandName);
        }
        throw error;
      }

      const unsignedInput = {
        entireCheckpointDetailJson,
        plan,
        capturedAt: options.capturedAt,
        git,
      } as const;
      let inspection: HandoffInspection;
      try {
        inspection = inspectHandoff({
          ...unsignedInput,
          signingIdentity: inspectionOnlyIdentity(diagnostic.identity),
        });
      } catch (error) {
        if (error instanceof HandoffError) {
          return handoffCoreFailure(dependencies, mode, commandName, error);
        }
        throw error;
      }

      if (!creating) {
        if (mode === "json") {
          writeJson(dependencies.stdout, {
            schema_version: 1,
            command: "handoff inspect",
            ok: true,
            exit_code: ExitCode.success,
            data: {
              review: inspection,
              effects: {
                signed: false,
                persisted: false,
                archive_published: false,
                provider_checkpoint_command_invoked: false,
              },
            },
          });
        } else {
          renderHandoffInspectionText(dependencies, inspection);
        }
        return ExitCode.success;
      }

      if (inspection.approvalDigest !== options.approvalDigest) {
        return handoffCoreFailure(
          dependencies,
          mode,
          "handoff create",
          new HandoffError(
            "approval_mismatch",
            "The approval digest does not match.",
          ),
        );
      }

      let approved;
      try {
        const createApproved =
          dependencies.device_identity.createApprovedHandoff;
        if (createApproved === undefined)
          throw new Error("runtime_unavailable");
        approved = await createApproved({
          ...unsignedInput,
          approvalDigest: options.approvalDigest,
        });
      } catch (error) {
        if (error instanceof DeviceIdentityError) {
          return handoffIdentityFailure(
            dependencies,
            mode,
            "handoff create",
            error.code,
          );
        }
        if (error instanceof HandoffError) {
          return handoffCoreFailure(
            dependencies,
            mode,
            "handoff create",
            error,
          );
        }
        throw error;
      }

      const independentVerification = verifyLogicalArchive(approved.archive, {
        trustedSignerFingerprints: [inspection.signer.fingerprint],
      });
      if (
        approved.inspection.approvalDigest !== inspection.approvalDigest ||
        approved.storeWritePlan.approvalDigest !== inspection.approvalDigest ||
        !independentVerification.integrity.valid ||
        !independentVerification.signer.signatureValid ||
        !independentVerification.signer.trusted ||
        independentVerification.signer.trust !== "trusted" ||
        independentVerification.signer.fingerprint !==
          inspection.signer.fingerprint ||
        independentVerification.archive.archiveId !==
          inspection.identifiers.archiveId ||
        independentVerification.archive.rootCheckpointId !==
          inspection.identifiers.checkpointId ||
        independentVerification.archive.payloadDigest !==
          inspection.proposedArchive.payloadDigest
      ) {
        return writeFixedError(
          dependencies,
          mode,
          "handoff create",
          ExitCode.archiveInvalid,
          "handoff_archive_reverification_failed",
          "The signed archive did not independently match the exact approved review.",
        );
      }

      let persisted;
      try {
        const persistApproved =
          dependencies.workspace_store.persistApprovedHandoff;
        if (persistApproved === undefined)
          throw new Error("runtime_unavailable");
        persisted = await persistApproved(
          dependencies.cwd,
          approved.storeWritePlan,
        );
      } catch {
        if (mode === "json") {
          writeJson(dependencies.stdout, {
            schema_version: 1,
            command: "handoff create",
            ok: false,
            exit_code: ExitCode.storeInvalid,
            error: {
              code: "handoff_store_persistence_incomplete",
              message:
                "The exact approved store plan did not complete; an idempotent retry is safe.",
            },
            data: {
              store: "partial-or-unknown",
              archive: "not-published",
              retry_safe: true,
            },
          });
        } else {
          dependencies.stderr.write(
            "The exact approved store plan did not complete; no archive was published and an idempotent retry is safe.\n",
          );
        }
        return ExitCode.storeInvalid;
      }

      let publication;
      try {
        publication = await dependencies.handoff_files.publishArchive(
          options.outputPath ?? "",
          approved.archive,
        );
      } catch (error) {
        const fileError =
          error instanceof HandoffFileError
            ? error
            : new HandoffFileError("archive_publish_failed");
        const exitCode =
          fileError.code === "output_exists" ||
          fileError.code === "output_unsafe"
            ? ExitCode.notReady
            : ExitCode.archiveInvalid;
        const message =
          fileError.code === "output_exists"
            ? "The archive output became unavailable after the exact store plan completed; retry with a new output directory."
            : "The archive was not published after the exact store plan completed; retrying publication through handoff create is safe.";
        if (mode === "json") {
          writeJson(dependencies.stdout, {
            schema_version: 1,
            command: "handoff create",
            ok: false,
            exit_code: exitCode,
            error: {
              code: `handoff_${fileError.code}`,
              message,
            },
            data: {
              store: "complete",
              archive: "not-published",
              retry_safe: true,
            },
          });
        } else {
          dependencies.stderr.write(`${message}\n`);
        }
        return exitCode;
      }

      const blobDispositions = {
        stored: persisted.blobs.filter(
          (result) => result.disposition === "stored",
        ).length,
        existing: persisted.blobs.filter(
          (result) => result.disposition === "existing",
        ).length,
      };
      const eventDispositions = {
        stored: persisted.events.filter(
          (result) => result.disposition === "stored",
        ).length,
        existing: persisted.events.filter(
          (result) => result.disposition === "existing",
        ).length,
      };
      if (mode === "json") {
        writeJson(dependencies.stdout, {
          schema_version: 1,
          command: "handoff create",
          ok: true,
          exit_code: ExitCode.success,
          data: {
            approval_digest: inspection.approvalDigest,
            archive: {
              archive_id: inspection.identifiers.archiveId,
              checkpoint_id: inspection.identifiers.checkpointId,
              payload_digest: inspection.proposedArchive.payloadDigest,
              entry_count: publication.entryCount,
              total_bytes: publication.totalBytes,
              published: true,
            },
            signer: {
              fingerprint: inspection.signer.fingerprint,
              trusted: true,
            },
            verification: {
              offline: true,
              integrity_valid: independentVerification.integrity.valid,
              signature_valid: independentVerification.signer.signatureValid,
              approval_recomputed: true,
            },
            store: {
              complete: true,
              blobs: blobDispositions,
              events: eventDispositions,
            },
          },
        });
      } else {
        dependencies.stdout.write(
          `Created approved handoff ${inspection.identifiers.archiveId}.\nApproval: ${inspection.approvalDigest}\nSigner: ${inspection.signer.fingerprint}\nStore: complete (${persisted.blobs.length} blobs, ${persisted.events.length} events).\nArchive: atomically published (${publication.entryCount} entries, ${publication.totalBytes} bytes).\n`,
        );
      }
      return ExitCode.success;
    }

    if (command[0] === "resume" && command[1] === "compile") {
      const options = parseScopedOptions(
        command.slice(2),
        ["--target", "--max-items", "--max-bytes", "--trust"],
        ["--allow-untrusted-signer"],
      );
      if ("error" in options) {
        return writeUsageError(dependencies, mode, options.error);
      }
      if (options.positionals.length !== 1) {
        return writeUsageError(
          dependencies,
          mode,
          "resume compile requires exactly one archive directory.",
        );
      }
      const targetValue = options.values.get("--target");
      if (targetValue !== "codex" && targetValue !== "claude") {
        return writeUsageError(
          dependencies,
          mode,
          "--target must be codex or claude.",
        );
      }
      const maxItems = parsePositiveInteger(
        "--max-items",
        options.values.get("--max-items"),
      );
      if (typeof maxItems !== "number") {
        return writeUsageError(dependencies, mode, maxItems.error);
      }
      const maxBytes = parsePositiveInteger(
        "--max-bytes",
        options.values.get("--max-bytes"),
      );
      if (typeof maxBytes !== "number") {
        return writeUsageError(dependencies, mode, maxBytes.error);
      }
      const signerPolicy = parseSignerPolicy(options);
      if ("error" in signerPolicy) {
        return writeUsageError(dependencies, mode, signerPolicy.error);
      }
      const { trustedSignerFingerprint, integrityOnlyAcknowledged } =
        signerPolicy;

      let archive;
      try {
        archive = await dependencies.archive_loader.load(
          options.positionals[0] ?? "",
        );
      } catch {
        return writeFixedError(
          dependencies,
          mode,
          "resume compile",
          ExitCode.archiveInvalid,
          "archive_load_failed",
          "The archive directory could not be loaded safely.",
        );
      }
      const verification = verifyLogicalArchive(archive, {
        ...(trustedSignerFingerprint === null
          ? {}
          : { trustedSignerFingerprints: [trustedSignerFingerprint] }),
      });
      if (
        !verification.integrity.valid ||
        !verification.signer.signatureValid
      ) {
        return writeFixedError(
          dependencies,
          mode,
          "resume compile",
          ExitCode.archiveInvalid,
          "archive_invalid",
          "The archive failed offline integrity verification.",
        );
      }
      if (
        trustedSignerFingerprint !== null &&
        (verification.signer.trust !== "trusted" ||
          !verification.signer.trusted)
      ) {
        return writeFixedError(
          dependencies,
          mode,
          "resume compile",
          ExitCode.signerUntrusted,
          "signer_untrusted",
          "The archive signer does not match the configured trust anchor.",
        );
      }

      let compilation;
      try {
        compilation = compileResumeBundle({
          archive,
          verification,
          target: targetValue as ResumeTarget,
          budget: { maxItems, maxUtf8Bytes: maxBytes },
        });
      } catch (error) {
        if (error instanceof ResumeCompileError) {
          if (error.code === "untrusted_signer") {
            return writeFixedError(
              dependencies,
              mode,
              "resume compile",
              ExitCode.signerUntrusted,
              "signer_untrusted",
              "The archive signer does not match the configured trust anchor.",
            );
          }
          if (
            error.code === "invalid_budget" ||
            error.code === "budget_too_small"
          ) {
            return writeUsageError(
              dependencies,
              mode,
              "The declared resume budget cannot contain the mandatory handoff.",
            );
          }
          return writeFixedError(
            dependencies,
            mode,
            "resume compile",
            ExitCode.archiveInvalid,
            "archive_not_compilable",
            "The verified archive cannot be compiled into a v0 resume bundle.",
          );
        }
        throw error;
      }

      if (mode === "json") {
        writeJson(dependencies.stdout, {
          schema_version: 1,
          command: "resume compile",
          ok: true,
          exit_code: ExitCode.success,
          data: {
            bundle: compilation.bundle,
            serialization: {
              bundle_json: {
                digest: sha256(Buffer.from(compilation.json, "utf8")),
                byte_length: Buffer.byteLength(compilation.json, "utf8"),
              },
              markdown: {
                digest: sha256(Buffer.from(compilation.markdown, "utf8")),
                byte_length: Buffer.byteLength(compilation.markdown, "utf8"),
              },
            },
            archive_reverified_offline: true,
            signer: {
              trust: verification.signer.trust,
              fingerprint: verification.signer.fingerprint,
              integrity_only_acknowledged: integrityOnlyAcknowledged,
            },
          },
        });
      } else {
        dependencies.stdout.write(compilation.markdown);
      }
      return ExitCode.success;
    }

    if (command[0] === "archive" && command[1] === "verify") {
      const options = parseScopedOptions(
        command.slice(2),
        ["--trust", "--repo"],
        ["--allow-untrusted-signer"],
      );
      if ("error" in options) {
        return writeUsageError(dependencies, mode, options.error);
      }
      if (options.positionals.length !== 1) {
        return writeUsageError(
          dependencies,
          mode,
          "archive verify requires exactly one archive directory.",
        );
      }
      const signerPolicy = parseSignerPolicy(options);
      if ("error" in signerPolicy) {
        return writeUsageError(dependencies, mode, signerPolicy.error);
      }
      const { trustedSignerFingerprint, integrityOnlyAcknowledged } =
        signerPolicy;
      let archive;
      try {
        archive = await dependencies.archive_loader.load(
          options.positionals[0] ?? "",
        );
      } catch {
        if (mode === "json") {
          writeJson(dependencies.stdout, {
            schema_version: 1,
            command: "archive verify",
            ok: false,
            exit_code: ExitCode.archiveInvalid,
            error: {
              code: "archive_load_failed",
              message: "The archive directory could not be loaded safely.",
            },
          });
        } else {
          dependencies.stderr.write(
            "The archive directory could not be loaded safely.\n",
          );
        }
        return ExitCode.archiveInvalid;
      }
      const internalVerification = verifyLogicalArchive(archive, {
        ...(trustedSignerFingerprint === null
          ? {}
          : { trustedSignerFingerprints: [trustedSignerFingerprint] }),
      });
      let externalRepositoryVerification: ExternalRepositoryVerification = {
        status: "not-checked",
      };
      const requestedRepository = options.values.get("--repo");
      if (
        requestedRepository !== undefined &&
        internalVerification.integrity.valid &&
        internalVerification.signer.signatureValid &&
        (trustedSignerFingerprint === null ||
          (internalVerification.signer.trust === "trusted" &&
            internalVerification.signer.trusted))
      ) {
        const declaredState = readVerifiedRootGitState(
          archive,
          internalVerification,
        );
        if (declaredState === null) {
          externalRepositoryVerification = {
            status: "unavailable",
            reason: "declared_state_unavailable",
          };
        } else {
          try {
            externalRepositoryVerification =
              await dependencies.git_state.verify({
                cwd: requestedRepository,
                declaredState,
              });
          } catch {
            externalRepositoryVerification = {
              status: "unavailable",
              reason: "git_unavailable",
            };
          }
        }
      }
      const verification: ArchiveVerificationResult = {
        ...internalVerification,
        externalRepositoryVerification,
      };
      const exitCode =
        !verification.integrity.valid || !verification.signer.signatureValid
          ? ExitCode.archiveInvalid
          : trustedSignerFingerprint !== null &&
              (verification.signer.trust !== "trusted" ||
                !verification.signer.trusted)
            ? ExitCode.signerUntrusted
            : requestedRepository !== undefined &&
                verification.externalRepositoryVerification.status !== "matched"
              ? ExitCode.notReady
              : ExitCode.success;
      if (mode === "json") {
        writeJson(dependencies.stdout, {
          schema_version: 1,
          command: "archive verify",
          ok: exitCode === ExitCode.success,
          exit_code: exitCode,
          data: {
            ...verification,
            operator_policy: {
              integrity_only_acknowledged: integrityOnlyAcknowledged,
            },
          },
        });
      } else {
        renderArchiveVerificationText(dependencies, verification);
      }
      return exitCode;
    }

    const unknownOption = command.find((argument) => argument.startsWith("-"));
    if (unknownOption !== undefined) {
      return writeUsageError(
        dependencies,
        mode,
        `Unknown option: ${unknownOption}`,
      );
    }
    return writeUsageError(dependencies, mode, "Unknown command.");
  } catch {
    if (mode === "json") {
      writeJson(dependencies.stdout, {
        schema_version: 1,
        command: command.join(" "),
        ok: false,
        exit_code: ExitCode.internalError,
        error: {
          code: "internal_error",
          message: "The command failed unexpectedly.",
        },
      });
    } else {
      dependencies.stderr.write("The command failed unexpectedly.\n");
    }
    return ExitCode.internalError;
  }
}
