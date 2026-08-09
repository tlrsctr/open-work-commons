# Developer-preview support matrix

This matrix describes the intended continuous-integration boundary for the source repository. It is not a long-term support or semantic-versioning commitment.

## Tested environments

| Capability                                                  | Ubuntu 24.04                | macOS 14                    | Windows     | Notes                                                                  |
| ----------------------------------------------------------- | --------------------------- | --------------------------- | ----------- | ---------------------------------------------------------------------- |
| Node.js 22                                                  | CI target                   | CI target                   | Not tested  | Minimum tested major                                                   |
| Node.js 24                                                  | CI target                   | CI target                   | Not tested  | Current tested major                                                   |
| Locked install, typecheck, tests, benchmarks, and build     | CI target                   | CI target                   | Not tested  | Source checkout only                                                   |
| Owner-only `.owc` store and Ed25519 file identity           | CI smoke                    | CI smoke                    | Unsupported | POSIX permission model                                                 |
| Exact local Git capture                                     | CI smoke                    | CI smoke                    | Unsupported | Requires a normal non-shallow checkout or explicit repository identity |
| Handoff inspect, exact approval, and create                 | CI smoke                    | CI smoke                    | Unsupported | Uses committed synthetic Entire input                                  |
| Offline archive verification and bounded resume compilation | CI smoke                    | CI smoke                    | Unsupported | No provider, model, account, or hosted API required                    |
| External local Git-state comparison                         | CI smoke                    | CI smoke                    | Unsupported | Read-only; reported separately from archive integrity                  |
| Entire 0.9 local status and discovery adapter               | Implemented, not CI-enabled | Implemented, not CI-enabled | Unsupported | Entire is optional and not installed in CI                             |

“CI smoke” means the workflow executes the capability on every listed operating-system and Node.js pair. It does not mean the project has completed field testing, performance qualification, or a security audit.

## Required tools

| Tool    | Supported boundary                                                                                                      |
| ------- | ----------------------------------------------------------------------------------------------------------------------- |
| Node.js | Major 22 or 24                                                                                                          |
| pnpm    | 11.16, pinned by `packageManager` and CI                                                                                |
| Git     | A locally invokable Git with a committed `HEAD`; no remote is required for capture or comparison                        |
| Entire  | Optional 0.9.x for local provider status/discovery; not required when supplying already-reviewed checkpoint-detail JSON |

## Distribution boundary

- The repository is currently source-only and its root package is private at version `0.0.0`.
- There is no npm package, Homebrew formula, standalone executable, container image, signed release artifact, or stable update channel.
- The archive writer publishes an owner-only unpacked directory. `.owc.tar.zst` container encoding is not implemented.
- The device identity uses an owner-only local file adapter. OS keychains, hardware keys, revocation, recovery, and multi-device trust are not implemented.
- Schema and CLI compatibility may change before the first tagged alpha; generated archives identify their explicit v0.1 formats.

## Offline meaning

“Offline verification” means the verifier consumes only the supplied archive bytes and optional local repository, performs no network request, and requires no provider login, model call, or vendor account. Installing dependencies and obtaining the source checkout are separate provisioning steps and may require network access.

CI does not claim to place the whole runner in a network namespace. The offline guarantee belongs to the bounded verifier implementation and its dependency-free runtime path, while the smoke test demonstrates that no provider setup is required.
