import { resolve } from "node:path";

import {
  LocalFileDeviceIdentityStore,
  type DeviceIdentityDiagnostic,
  type PublicDeviceIdentity,
} from "../../../packages/identity/src/index.js";
import {
  createApprovedHandoff,
  type ApprovedHandoff,
  type CreateApprovedHandoffInput,
} from "../../../packages/handoff/src/index.js";

export type UnsignedApprovedHandoffInput = Omit<
  CreateApprovedHandoffInput,
  "signingIdentity"
>;

export interface DeviceIdentityRuntime {
  /** Open or create the identity under an already initialized private store. */
  openOrCreate(privateDirectory: string): Promise<PublicDeviceIdentity>;
  /** Diagnose the configured workspace identity without creating any files. */
  diagnose(): Promise<DeviceIdentityDiagnostic>;
  /**
   * Open the existing device capability and sign one exactly approved handoff.
   * The capability and its private key bytes never leave this runtime.
   */
  createApprovedHandoff?(
    input: UnsignedApprovedHandoffInput,
  ): Promise<ApprovedHandoff>;
}

/**
 * Keep the signing capability inside this adapter. The CLI receives only the
 * package-validated public identity and can never serialize the private key.
 */
export function createDeviceIdentityRuntime(
  workspaceDirectory: string,
): DeviceIdentityRuntime {
  const configuredStore = new LocalFileDeviceIdentityStore(
    resolve(workspaceDirectory, ".owc"),
  );
  return {
    async openOrCreate(privateDirectory) {
      const signingIdentity = await new LocalFileDeviceIdentityStore(
        privateDirectory,
      ).openOrCreate();
      return signingIdentity.publicIdentity;
    },
    diagnose() {
      return configuredStore.diagnose();
    },
    async createApprovedHandoff(input) {
      const signingIdentity = await configuredStore.open();
      return createApprovedHandoff({ ...input, signingIdentity });
    },
  };
}
