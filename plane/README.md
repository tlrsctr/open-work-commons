# Plane bootstrap

`v0-backlog.json` is the deterministic Git-owned specification for the first Open Work Commons backlog.

The manifest owns issue identity, title, exact managed description HTML, priority, parent, and `blocked_by` relations. Plane owns execution status after initial creation, assignees, dates, comments, discussion, and evidence. The bootstrap intentionally refuses to overwrite or remove unexpected existing state; preserving only the embedded key or digest marker is not sufficient to pass reconciliation.

## Commands

Validate the local manifest without a Plane credential or network call:

```sh
pnpm plane:validate
```

After loading `PLANE_API_BASE_URL`, `PLANE_WORKSPACE_SLUG`, and `PLANE_API_TOKEN` through a local configuration and secret mechanism, perform a read-only comparison:

```sh
pnpm plane:check
```

Create only missing items and missing declared blocker relations, then refetch and verify every managed field:

```sh
pnpm plane:apply
```

The apply path creates one item at a time, never automatically retries an ambiguous mutation, verifies exact project and state identity, and stops on managed-field drift or unexpected relations. Re-run `plane:check` after any apply.

Requests are paced at 1.05 seconds by default so a bootstrap stays below Plane's default 60-request-per-minute API-key limit. `PLANE_REQUEST_INTERVAL_MS` may raise that delay; values below 250 milliseconds are refused. HTTP failures are never retried automatically.

`PLANE_WEB_BASE_URL` is optional and controls only the links printed after verification; it defaults to the API URL's origin.

Never commit a Plane host, private workspace topology, related private-project identifiers, or API token into the public manifest. Never place a token in command history. Rotate a credential immediately if its value appears in terminal, CI, tool, or chat output.
