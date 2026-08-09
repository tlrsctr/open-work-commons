import { spawn } from "node:child_process";

import {
  importEntireCheckpointDetail as projectEntireCheckpointDetail,
  importEntireCheckpointList as projectEntireCheckpointList,
  type EntireCheckpointImportOptions,
  type EntireCheckpointImportResult,
} from "./checkpoint-import.js";

export interface CommandInvocation {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd?: string;
}

export interface CommandResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

export type CommandRunner = (
  invocation: CommandInvocation,
) => Promise<CommandResult>;

export interface ProviderInspectionOptions {
  readonly cwd?: string;
}

export interface WorkCaptureProviderAdapter {
  readonly providerId: string;
  inspect(
    options?: ProviderInspectionOptions,
  ): Promise<ProviderCapabilityReport>;
  discoverCheckpoints(
    options?: ProviderInspectionOptions,
  ): Promise<EntireCheckpointDiscoveryResult>;
  importCheckpointList(
    input: string,
    options?: EntireCheckpointImportOptions,
  ): EntireCheckpointImportResult;
  importCheckpointDetail(
    input: string,
    options?: EntireCheckpointImportOptions,
  ): EntireCheckpointImportResult;
}

export type ProbeState = "known" | "unknown";

export interface ProviderCapabilityReport {
  readonly provider: {
    readonly id: "entire";
    readonly name: "Entire";
  };
  readonly installation: {
    readonly installed: boolean;
    readonly version: string | null;
    readonly supported: boolean;
    readonly minimumVersion: "0.9.0";
  };
  readonly repository: {
    readonly enabled: boolean | null;
    readonly state: ProbeState;
  };
  readonly capabilities: {
    readonly agents: {
      readonly available: boolean;
      readonly list: boolean;
      readonly add: boolean;
      readonly remove: boolean;
      readonly installed: readonly string[];
      readonly installedState: ProbeState;
    };
    readonly checkpoints: {
      readonly available: boolean;
      readonly list: boolean;
      readonly json: boolean;
      readonly pending: boolean;
      readonly sessionFilter: boolean;
      readonly detail: boolean;
      readonly detailJson: boolean;
      readonly localOnlyGuaranteed: false;
      readonly boundary: "provider-cli-may-fetch-remote-checkpoint-data";
    };
  };
  readonly access: {
    readonly localOnly: true;
    readonly accountRequired: false;
  };
  readonly dataPolicy: {
    readonly rawTranscripts: "excluded";
  };
  readonly diagnostics: readonly EntireAdapterDiagnostic[];
}

export type EntireAdapterDiagnostic =
  | "entire_not_installed"
  | "entire_version_unrecognized"
  | "entire_version_unsupported"
  | "entire_capability_probe_incomplete"
  | "entire_status_probe_failed"
  | "entire_status_unrecognized";

export type EntireCheckpointDiscoveryReason =
  | "entire_not_installed"
  | "entire_version_unsupported"
  | "structured_checkpoint_list_unavailable"
  | "structured_checkpoint_detail_unavailable"
  | "provider_cli_may_fetch_remote_checkpoint_data";

export interface EntireCheckpointDiscoveryResult {
  readonly status: "unavailable";
  readonly provider: "entire";
  readonly reason: EntireCheckpointDiscoveryReason;
  readonly capabilities: {
    readonly structuredList: boolean;
    readonly structuredDetail: boolean;
    readonly localOnlyGuaranteed: false;
  };
  readonly dataPolicy: {
    readonly rawTranscripts: "excluded";
    readonly unknownProviderFields: "excluded";
  };
  readonly diagnostics: readonly EntireAdapterDiagnostic[];
}

export interface EntireAdapterOptions {
  readonly runner?: CommandRunner;
  readonly binary?: string;
  readonly probeTimeoutMs?: number;
  readonly terminationGraceMs?: number;
}

interface Version {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly text: string;
}

type JsonRecord = Record<string, unknown>;

const MAX_CAPTURE_BYTES = 256 * 1024;
const DEFAULT_PROBE_TIMEOUT_MS = 5_000;
const MINIMUM_PROBE_TIMEOUT_MS = 50;
const MAXIMUM_PROBE_TIMEOUT_MS = 30_000;
const DEFAULT_TERMINATION_GRACE_MS = 250;
const MINIMUM_TERMINATION_GRACE_MS = 25;
const MAXIMUM_TERMINATION_GRACE_MS = 2_000;
const FORCED_SETTLEMENT_MS = 1_000;
const MINIMUM_VERSION = "0.9.0" as const;
const LOCAL_READ_ONLY_PROBES = new Set([
  JSON.stringify(["--version"]),
  JSON.stringify(["agent-help", "--json"]),
  JSON.stringify(["agent-help", "status", "--json"]),
  JSON.stringify(["agent-help", "agent", "--json"]),
  JSON.stringify(["agent-help", "checkpoint", "--json"]),
  JSON.stringify(["agent-help", "checkpoint", "list", "--json"]),
  JSON.stringify(["agent-help", "checkpoint", "explain", "--json"]),
  JSON.stringify(["status", "--json"]),
]);

type CommandFailureCode =
  | "entire_probe_spawn_failed"
  | "entire_probe_timed_out"
  | "entire_probe_output_limit_exceeded"
  | "entire_probe_forced_settlement";

class CommandFailure extends Error {
  readonly code: CommandFailureCode;

  constructor(code: CommandFailureCode) {
    super(code);
    this.name = "CommandFailure";
    this.code = code;
  }
}

const EMPTY_AGENTS = {
  available: false,
  list: false,
  add: false,
  remove: false,
  installed: [] as readonly string[],
  installedState: "unknown" as const,
};

const EMPTY_CHECKPOINTS = {
  available: false,
  list: false,
  json: false,
  pending: false,
  sessionFilter: false,
  detail: false,
  detailJson: false,
  localOnlyGuaranteed: false as const,
  boundary: "provider-cli-may-fetch-remote-checkpoint-data" as const,
};

export function createEntireAdapter(
  options: EntireAdapterOptions = {},
): WorkCaptureProviderAdapter {
  const runner =
    options.runner ??
    createNodeCommandRunner({
      probeTimeoutMs: readBoundedDuration(
        options.probeTimeoutMs,
        DEFAULT_PROBE_TIMEOUT_MS,
        MINIMUM_PROBE_TIMEOUT_MS,
        MAXIMUM_PROBE_TIMEOUT_MS,
      ),
      terminationGraceMs: readBoundedDuration(
        options.terminationGraceMs,
        DEFAULT_TERMINATION_GRACE_MS,
        MINIMUM_TERMINATION_GRACE_MS,
        MAXIMUM_TERMINATION_GRACE_MS,
      ),
    });
  const binary = options.binary ?? "entire";

  return {
    providerId: "entire",
    async inspect(
      inspectionOptions: ProviderInspectionOptions = {},
    ): Promise<ProviderCapabilityReport> {
      return inspectEntire(binary, runner, inspectionOptions);
    },
    async discoverCheckpoints(
      inspectionOptions: ProviderInspectionOptions = {},
    ): Promise<EntireCheckpointDiscoveryResult> {
      const report = await inspectEntire(binary, runner, inspectionOptions);
      return createCheckpointDiscoveryResult(report);
    },
    importCheckpointList(
      input: string,
      importOptions: EntireCheckpointImportOptions = {},
    ): EntireCheckpointImportResult {
      return projectEntireCheckpointList(input, importOptions);
    },
    importCheckpointDetail(
      input: string,
      importOptions: EntireCheckpointImportOptions = {},
    ): EntireCheckpointImportResult {
      return projectEntireCheckpointDetail(input, importOptions);
    },
  };
}

interface NodeCommandRunnerOptions {
  readonly probeTimeoutMs: number;
  readonly terminationGraceMs: number;
}

function createNodeCommandRunner(
  options: NodeCommandRunnerOptions,
): CommandRunner {
  return async (invocation): Promise<CommandResult> =>
    new Promise((resolve, reject) => {
      let child: ReturnType<typeof spawn>;
      try {
        child = spawn(invocation.command, [...invocation.args], {
          shell: false,
          windowsHide: true,
          stdio: ["ignore", "pipe", "pipe"],
          ...(invocation.cwd === undefined ? {} : { cwd: invocation.cwd }),
        });
      } catch {
        reject(new CommandFailure("entire_probe_spawn_failed"));
        return;
      }

      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      let capturedBytes = 0;
      let settled = false;
      let exited = false;
      let failure: CommandFailureCode | null = null;
      let graceTimer: NodeJS.Timeout | undefined;
      let forcedSettlementTimer: NodeJS.Timeout | undefined;

      const deadlineTimer = setTimeout(() => {
        beginTermination("entire_probe_timed_out");
      }, options.probeTimeoutMs);

      const clearTimers = (): void => {
        clearTimeout(deadlineTimer);
        if (graceTimer !== undefined) clearTimeout(graceTimer);
        if (forcedSettlementTimer !== undefined) {
          clearTimeout(forcedSettlementTimer);
        }
      };

      const stopCapturing = (): void => {
        stdoutChunks.length = 0;
        stderrChunks.length = 0;
      };

      const cleanup = (): void => {
        clearTimers();
        child.stdout?.off("data", onStdoutData);
        child.stderr?.off("data", onStderrData);
        child.off("error", onError);
        child.off("exit", onExit);
        child.off("close", onClose);
      };

      const settleFailure = (code: CommandFailureCode): void => {
        if (settled) return;
        settled = true;
        stopCapturing();
        cleanup();
        reject(new CommandFailure(code));
      };

      const settleSuccess = (exitCode: number): void => {
        if (settled) return;
        settled = true;
        const stdout = Buffer.concat(stdoutChunks).toString("utf8");
        const stderr = Buffer.concat(stderrChunks).toString("utf8");
        cleanup();
        resolve({ exitCode, stdout, stderr });
      };

      const forceKill = (): void => {
        if (settled) return;
        try {
          child.kill("SIGKILL");
        } catch {
          // The fixed settlement watchdog below handles every kill failure.
        }
        forcedSettlementTimer = setTimeout(() => {
          child.stdout?.destroy();
          child.stderr?.destroy();
          child.unref();
          child.on("error", ignoreLateChildError);
          settleFailure("entire_probe_forced_settlement");
        }, FORCED_SETTLEMENT_MS);
      };

      function beginTermination(code: CommandFailureCode): void {
        if (settled || failure !== null) return;
        failure = code;
        stopCapturing();
        if (exited) {
          child.stdout?.destroy();
          child.stderr?.destroy();
          settleFailure(code);
          return;
        }
        try {
          child.kill("SIGTERM");
        } catch {
          // SIGKILL and the settlement watchdog remain authoritative.
        }
        graceTimer = setTimeout(forceKill, options.terminationGraceMs);
      }

      const capture = (chunks: Buffer[], chunk: unknown): void => {
        if (settled || failure !== null) return;
        const bytes = Buffer.isBuffer(chunk)
          ? chunk
          : Buffer.from(String(chunk), "utf8");
        capturedBytes += bytes.byteLength;
        if (capturedBytes > MAX_CAPTURE_BYTES) {
          beginTermination("entire_probe_output_limit_exceeded");
          return;
        }
        chunks.push(bytes);
      };

      function onStdoutData(chunk: unknown): void {
        capture(stdoutChunks, chunk);
      }

      function onStderrData(chunk: unknown): void {
        capture(stderrChunks, chunk);
      }

      function onError(): void {
        if (settled) return;
        if (child.pid === undefined) {
          child.stdout?.destroy();
          child.stderr?.destroy();
          settleFailure("entire_probe_spawn_failed");
          return;
        }
        beginTermination("entire_probe_spawn_failed");
      }

      function onExit(): void {
        exited = true;
        if (failure !== null) {
          child.stdout?.destroy();
          child.stderr?.destroy();
          settleFailure(failure);
        }
      }

      function onClose(code: number | null): void {
        exited = true;
        if (failure !== null) {
          settleFailure(failure);
          return;
        }
        settleSuccess(code ?? 1);
      }

      function ignoreLateChildError(): void {
        // A forced-settlement child has already been killed and detached.
      }

      child.stdout?.on("data", onStdoutData);
      child.stderr?.on("data", onStderrData);
      child.once("error", onError);
      child.once("exit", onExit);
      child.once("close", onClose);
    });
}

function readBoundedDuration(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const duration = value ?? fallback;
  if (
    !Number.isSafeInteger(duration) ||
    duration < minimum ||
    duration > maximum
  ) {
    throw new Error("invalid_entire_adapter_timeout");
  }
  return duration;
}

async function inspectEntire(
  binary: string,
  runner: CommandRunner,
  options: ProviderInspectionOptions,
): Promise<ProviderCapabilityReport> {
  const diagnostics = new Set<EntireAdapterDiagnostic>();
  const versionResult = await runProbe(
    runner,
    binary,
    ["--version"],
    options.cwd,
  );

  if (versionResult === null || versionResult.exitCode === 127) {
    diagnostics.add("entire_not_installed");
    return createReport({
      installed: false,
      version: null,
      supported: false,
      enabled: null,
      agents: EMPTY_AGENTS,
      checkpoints: EMPTY_CHECKPOINTS,
      diagnostics,
    });
  }

  const version = parseVersion(versionResult.stdout);
  if (version === null) {
    diagnostics.add("entire_version_unrecognized");
    return createReport({
      installed: true,
      version: null,
      supported: false,
      enabled: null,
      agents: EMPTY_AGENTS,
      checkpoints: EMPTY_CHECKPOINTS,
      diagnostics,
    });
  }

  if (!isSupportedVersion(version)) {
    diagnostics.add("entire_version_unsupported");
    return createReport({
      installed: true,
      version: version.text,
      supported: false,
      enabled: null,
      agents: EMPTY_AGENTS,
      checkpoints: EMPTY_CHECKPOINTS,
      diagnostics,
    });
  }

  const rootHelp = await readAgentHelp(runner, binary, [], options.cwd);
  const statusHelp = await readAgentHelp(
    runner,
    binary,
    ["status"],
    options.cwd,
  );
  const agentHelp = await readAgentHelp(runner, binary, ["agent"], options.cwd);
  const checkpointHelp = await readAgentHelp(
    runner,
    binary,
    ["checkpoint"],
    options.cwd,
  );
  const checkpointListHelp = await readAgentHelp(
    runner,
    binary,
    ["checkpoint", "list"],
    options.cwd,
  );
  const checkpointExplainHelp = await readAgentHelp(
    runner,
    binary,
    ["checkpoint", "explain"],
    options.cwd,
  );

  if (
    rootHelp === null ||
    statusHelp === null ||
    agentHelp === null ||
    checkpointHelp === null ||
    checkpointListHelp === null ||
    checkpointExplainHelp === null
  ) {
    diagnostics.add("entire_capability_probe_incomplete");
  }

  const rootCommands = readSubcommands(rootHelp);
  const agentCommands = readSubcommands(agentHelp);
  const checkpointCommands = readSubcommands(checkpointHelp);
  const statusFlags = readFlags(statusHelp);
  const checkpointListFlags = readFlags(checkpointListHelp);
  const checkpointExplainFlags = readFlags(checkpointExplainHelp);
  const canReadStatus = rootCommands.has("status") && statusFlags.has("json");

  let enabled: boolean | null = null;
  let installedAgents: readonly string[] = [];
  let installedAgentsState: ProbeState = "unknown";

  if (canReadStatus) {
    const statusResult = await runProbe(
      runner,
      binary,
      ["status", "--json"],
      options.cwd,
    );
    if (statusResult === null || statusResult.exitCode !== 0) {
      diagnostics.add("entire_status_probe_failed");
    } else {
      const status = parseJsonRecord(statusResult.stdout);
      if (status === null) {
        diagnostics.add("entire_status_unrecognized");
      } else {
        enabled = readEnabled(status);
        if (enabled === null) {
          diagnostics.add("entire_status_unrecognized");
        }
        const agents = readInstalledAgents(status);
        installedAgents = agents.ids;
        installedAgentsState = agents.state;
      }
    }
  }

  return createReport({
    installed: true,
    version: version.text,
    supported: true,
    enabled,
    agents: {
      available: rootCommands.has("agent"),
      list: agentCommands.has("list"),
      add: agentCommands.has("add"),
      remove: agentCommands.has("remove"),
      installed: installedAgents,
      installedState: installedAgentsState,
    },
    checkpoints: {
      available: rootCommands.has("checkpoint"),
      list: checkpointCommands.has("list"),
      json: checkpointListFlags.has("json"),
      pending: checkpointListFlags.has("pending"),
      sessionFilter: checkpointListFlags.has("session"),
      detail: checkpointCommands.has("explain"),
      detailJson: checkpointExplainFlags.has("json"),
      localOnlyGuaranteed: false,
      boundary: "provider-cli-may-fetch-remote-checkpoint-data",
    },
    diagnostics,
  });
}

function createCheckpointDiscoveryResult(
  report: ProviderCapabilityReport,
): EntireCheckpointDiscoveryResult {
  const checkpoints = report.capabilities.checkpoints;
  const structuredList = checkpoints.list && checkpoints.json;
  const structuredDetail = checkpoints.detail && checkpoints.detailJson;
  let reason: EntireCheckpointDiscoveryReason;

  if (!report.installation.installed) {
    reason = "entire_not_installed";
  } else if (!report.installation.supported) {
    reason = "entire_version_unsupported";
  } else if (!structuredList) {
    reason = "structured_checkpoint_list_unavailable";
  } else if (!structuredDetail) {
    reason = "structured_checkpoint_detail_unavailable";
  } else {
    // Entire 0.9 list/detail JSON paths are non-mutating at the command layer,
    // but their implementation can discover and fetch remote checkpoint refs.
    // Strict-local discovery therefore returns a capability result and never
    // invokes either command. Callers may import an explicitly supplied JSON
    // export through the pure allowlist projectors instead.
    reason = "provider_cli_may_fetch_remote_checkpoint_data";
  }

  return {
    status: "unavailable",
    provider: "entire",
    reason,
    capabilities: {
      structuredList,
      structuredDetail,
      localOnlyGuaranteed: false,
    },
    dataPolicy: {
      rawTranscripts: "excluded",
      unknownProviderFields: "excluded",
    },
    diagnostics: report.diagnostics,
  };
}

interface CreateReportInput {
  readonly installed: boolean;
  readonly version: string | null;
  readonly supported: boolean;
  readonly enabled: boolean | null;
  readonly agents: ProviderCapabilityReport["capabilities"]["agents"];
  readonly checkpoints: ProviderCapabilityReport["capabilities"]["checkpoints"];
  readonly diagnostics: ReadonlySet<EntireAdapterDiagnostic>;
}

function createReport(input: CreateReportInput): ProviderCapabilityReport {
  return {
    provider: { id: "entire", name: "Entire" },
    installation: {
      installed: input.installed,
      version: input.version,
      supported: input.supported,
      minimumVersion: MINIMUM_VERSION,
    },
    repository: {
      enabled: input.enabled,
      state: input.enabled === null ? "unknown" : "known",
    },
    capabilities: {
      agents: input.agents,
      checkpoints: input.checkpoints,
    },
    access: { localOnly: true, accountRequired: false },
    dataPolicy: { rawTranscripts: "excluded" },
    diagnostics: [...input.diagnostics],
  };
}

async function readAgentHelp(
  runner: CommandRunner,
  binary: string,
  commandPath: readonly string[],
  cwd: string | undefined,
): Promise<JsonRecord | null> {
  const result = await runProbe(
    runner,
    binary,
    ["agent-help", ...commandPath, "--json"],
    cwd,
  );
  if (result === null || result.exitCode !== 0) {
    return null;
  }
  return parseJsonRecord(result.stdout);
}

async function runProbe(
  runner: CommandRunner,
  binary: string,
  args: readonly string[],
  cwd: string | undefined,
): Promise<CommandResult | null> {
  assertLocalReadOnlyProbe(args);
  try {
    const invocation: CommandInvocation =
      cwd === undefined
        ? { command: binary, args }
        : { command: binary, args, cwd };
    return await runner(invocation);
  } catch {
    return null;
  }
}

function assertLocalReadOnlyProbe(args: readonly string[]): void {
  if (!LOCAL_READ_ONLY_PROBES.has(JSON.stringify(args))) {
    throw new Error("Entire adapter attempted a non-local or mutating command");
  }
}

function parseVersion(output: string): Version | null {
  const match = output.match(/\b(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?\b/);
  if (match === null) {
    return null;
  }
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (![major, minor, patch].every(Number.isSafeInteger)) {
    return null;
  }
  return { major, minor, patch, text: `${major}.${minor}.${patch}` };
}

function isSupportedVersion(version: Version): boolean {
  return version.major > 0 || (version.major === 0 && version.minor >= 9);
}

function parseJsonRecord(output: string): JsonRecord | null {
  try {
    const value: unknown = JSON.parse(output);
    return isRecord(value) ? value : null;
  } catch {
    return null;
  }
}

function readSubcommands(help: JsonRecord | null): ReadonlySet<string> {
  const commands = new Set<string>();
  if (help === null || !Array.isArray(help.subcommands)) {
    return commands;
  }
  for (const item of help.subcommands) {
    if (isRecord(item) && typeof item.name === "string") {
      commands.add(item.name);
    }
  }
  return commands;
}

function readFlags(help: JsonRecord | null): ReadonlySet<string> {
  const flags = new Set<string>();
  if (help === null || !Array.isArray(help.flags)) {
    return flags;
  }
  for (const item of help.flags) {
    if (isRecord(item) && typeof item.name === "string") {
      flags.add(item.name);
    }
  }
  return flags;
}

function readEnabled(status: JsonRecord): boolean | null {
  for (const key of ["enabled", "is_enabled", "isEnabled"] as const) {
    const value = status[key];
    if (typeof value === "boolean") {
      return value;
    }
  }

  const statusValue = status.status;
  if (typeof statusValue === "string") {
    const normalized = statusValue.trim().toLowerCase();
    if (normalized === "enabled") return true;
    if (normalized === "disabled") return false;
  }

  for (const key of ["repository", "repo", "entire"] as const) {
    const nested = status[key];
    if (isRecord(nested)) {
      const enabled = readEnabled(nested);
      if (enabled !== null) return enabled;
    }
  }
  return null;
}

function readInstalledAgents(status: JsonRecord): {
  readonly ids: readonly string[];
  readonly state: ProbeState;
} {
  const containers: unknown[] = [];
  for (const key of [
    "agents",
    "agent",
    "integrations",
    "agent_integrations",
    "agentIntegrations",
  ] as const) {
    if (Object.hasOwn(status, key)) {
      containers.push(status[key]);
    }
  }
  if (isRecord(status.settings)) {
    for (const key of [
      "agents",
      "agent_integrations",
      "agentIntegrations",
    ] as const) {
      if (Object.hasOwn(status.settings, key)) {
        containers.push(status.settings[key]);
      }
    }
  }

  if (containers.length === 0) {
    return { ids: [], state: "unknown" };
  }

  const ids = new Set<string>();
  for (const container of containers) {
    collectAgentIds(container, ids);
  }
  return { ids: [...ids].sort(), state: "known" };
}

function collectAgentIds(value: unknown, ids: Set<string>): void {
  if (typeof value === "string") {
    const id = normalizeAgentId(value);
    if (id !== null) ids.add(id);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectAgentIds(item, ids);
    return;
  }
  if (!isRecord(value)) return;

  const explicitId = readExplicitAgentId(value);
  if (explicitId !== null && isInstalled(value)) {
    ids.add(explicitId);
  }

  if (explicitId === null) {
    for (const [key, entry] of Object.entries(value)) {
      const id = normalizeAgentId(key);
      if (id !== null && isInstalledMappingValue(entry)) {
        ids.add(id);
      }
    }
  }
}

function readExplicitAgentId(value: JsonRecord): string | null {
  for (const key of ["id", "name", "agent", "agent_id", "agentName"] as const) {
    if (typeof value[key] === "string") {
      return normalizeAgentId(value[key]);
    }
  }
  return null;
}

function isInstalled(value: JsonRecord): boolean {
  for (const key of ["installed", "enabled", "active"] as const) {
    if (typeof value[key] === "boolean") return value[key];
  }
  if (typeof value.status === "string") {
    return ["installed", "enabled", "active"].includes(
      value.status.trim().toLowerCase(),
    );
  }
  return true;
}

function isInstalledMappingValue(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (isRecord(value)) return isInstalled(value);
  return false;
}

function normalizeAgentId(input: string): string | null {
  const normalized = input
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (normalized.length === 0 || normalized.length > 64) {
    return null;
  }
  return normalized;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
