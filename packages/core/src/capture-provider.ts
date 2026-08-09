import { ExitCode, type ExitCodeValue } from "./exit-codes.js";

export const captureProviderStates = [
  "ready",
  "disabled",
  "unavailable",
  "error",
  "invalid_output",
] as const;

export type CaptureProviderState = (typeof captureProviderStates)[number];

export type CaptureProviderStatus = {
  schema_version: 1;
  provider: string;
  state: CaptureProviderState;
  capture_ready: boolean;
  message: string;
};

export interface CaptureProvider {
  readonly id: string;
  status(): Promise<CaptureProviderStatus>;
}

export function providerStatusExitCode(
  status: CaptureProviderStatus,
): ExitCodeValue {
  switch (status.state) {
    case "ready":
      return ExitCode.success;
    case "unavailable":
      return ExitCode.dependencyUnavailable;
    case "disabled":
      return ExitCode.notReady;
    case "error":
      return ExitCode.providerFailure;
    case "invalid_output":
      return ExitCode.invalidProviderOutput;
  }
}
