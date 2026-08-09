export const ExitCode = {
  success: 0,
  usage: 2,
  dependencyUnavailable: 3,
  notReady: 4,
  providerFailure: 5,
  invalidProviderOutput: 6,
  archiveInvalid: 7,
  signerUntrusted: 8,
  storeInvalid: 9,
  internalError: 70,
} as const;

export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode];

const exitCodePriority: Readonly<Record<ExitCodeValue, number>> = {
  [ExitCode.success]: 0,
  [ExitCode.usage]: 1,
  [ExitCode.dependencyUnavailable]: 2,
  [ExitCode.notReady]: 3,
  [ExitCode.providerFailure]: 4,
  [ExitCode.invalidProviderOutput]: 5,
  [ExitCode.archiveInvalid]: 6,
  [ExitCode.signerUntrusted]: 7,
  [ExitCode.storeInvalid]: 8,
  [ExitCode.internalError]: 9,
};

export function highestPriorityExitCode(
  exitCodes: readonly ExitCodeValue[],
): ExitCodeValue {
  return exitCodes.reduce<ExitCodeValue>(
    (selected, candidate) =>
      exitCodePriority[candidate] > exitCodePriority[selected]
        ? candidate
        : selected,
    ExitCode.success,
  );
}
