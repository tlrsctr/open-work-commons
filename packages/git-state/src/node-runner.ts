import { spawn } from "node:child_process";

import {
  GitStateCaptureError,
  type GitCommandRequest,
  type GitCommandResult,
  type GitCommandRunner,
} from "./types.js";

const STDERR_LIMIT_BYTES = 64 * 1024;

export interface NodeGitCommandRunnerOptions {
  readonly gitExecutable?: string;
  readonly environment?: NodeJS.ProcessEnv;
}

export function createNodeGitCommandRunner(
  options: NodeGitCommandRunnerOptions = {},
): GitCommandRunner {
  const gitExecutable = options.gitExecutable ?? "git";
  const environment = sanitizedGitEnvironment(
    options.environment ?? process.env,
  );

  return {
    run(request) {
      return runGit(gitExecutable, environment, request);
    },
  };
}

function runGit(
  gitExecutable: string,
  environment: NodeJS.ProcessEnv,
  request: GitCommandRequest,
): Promise<GitCommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(gitExecutable, request.args, {
      cwd: request.cwd,
      env: environment,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;

    const fail = (error: GitStateCaptureError): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill("SIGKILL");
      reject(error);
    };

    const timer = setTimeout(() => {
      fail(
        new GitStateCaptureError(
          "SUBPROCESS_ERROR",
          "Git command exceeded its execution deadline.",
        ),
      );
    }, request.timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.byteLength;
      if (stdoutBytes > request.maxStdoutBytes) {
        fail(
          new GitStateCaptureError(
            "OUTPUT_LIMIT_EXCEEDED",
            "Git command output exceeded the configured byte limit.",
          ),
        );
        return;
      }
      stdout.push(chunk);
    });

    child.stderr.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.byteLength;
      if (stderrBytes > STDERR_LIMIT_BYTES) {
        fail(
          new GitStateCaptureError(
            "OUTPUT_LIMIT_EXCEEDED",
            "Git diagnostic output exceeded the configured byte limit.",
          ),
        );
        return;
      }
      stderr.push(chunk);
    });

    child.once("error", () => {
      fail(
        new GitStateCaptureError(
          "SUBPROCESS_ERROR",
          "The Git executable could not be started.",
        ),
      );
    });

    child.once("close", (exitCode, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        exitCode,
        stdout: Buffer.concat(stdout, stdoutBytes),
        stderr: Buffer.concat(stderr, stderrBytes),
        signal,
      });
    });
  });
}

function sanitizedGitEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = { ...source };
  const exactVariables = [
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_ATTR_NOSYSTEM",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_DIFF_OPTS",
    "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_GRAFT_FILE",
    "GIT_GLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PAGER",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_TRACE",
    "GIT_WORK_TREE",
  ];

  for (const name of exactVariables) delete environment[name];
  for (const name of Object.keys(environment)) {
    if (/^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(name)) delete environment[name];
    if (/^GIT_TRACE(?:2|_)/.test(name)) delete environment[name];
  }

  environment.LC_ALL = "C";
  environment.LANG = "C";
  environment.GIT_ATTR_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL =
    process.platform === "win32" ? "NUL" : "/dev/null";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_NO_LAZY_FETCH = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_PAGER = "cat";
  environment.GIT_TERMINAL_PROMPT = "0";
  return environment;
}
