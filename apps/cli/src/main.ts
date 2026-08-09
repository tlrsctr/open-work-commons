#!/usr/bin/env node

import { runCli } from "./cli.js";
import {
  createNodeCommandRunner,
  nodeFileSystemProbe,
} from "./node-runtime.js";
import { createDirectoryArchiveLoader } from "./archive-directory.js";
import { createDeviceIdentityRuntime } from "./device-identity-runtime.js";
import { createGitStateRuntime } from "./git-state-runtime.js";
import { createHandoffFileRuntime } from "./handoff-file-runtime.js";
import { createWorkspaceStoreRuntime } from "./store-runtime.js";

const cwd = process.cwd();

process.exitCode = await runCli(process.argv.slice(2), {
  cwd,
  node_version: process.version,
  file_system: nodeFileSystemProbe,
  command_runner: createNodeCommandRunner(),
  archive_loader: createDirectoryArchiveLoader(),
  device_identity: createDeviceIdentityRuntime(cwd),
  git_state: createGitStateRuntime(),
  handoff_files: createHandoffFileRuntime(cwd),
  workspace_store: createWorkspaceStoreRuntime(),
  clock: { now: () => new Date() },
  stdout: process.stdout,
  stderr: process.stderr,
});
