import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import process from "node:process";

type WorkItemSpec = {
  key: string;
  title: string;
  priority: "none" | "urgent" | "high" | "medium" | "low";
  state: string;
  parent: string | null;
  blocked_by: string[];
  outcome: string;
  journey: string;
  scope: string[];
  acceptance: string[];
  non_goals: string[];
  evidence: string[];
  related: string[];
};

type Manifest = {
  schema_version: number;
  project: { identifier: string; name: string };
  work_items: WorkItemSpec[];
};

type Project = { id: string; identifier: string; name: string };
type State = { id: string; name: string };
type WorkItem = {
  id: string;
  sequence_id: number;
  name: string;
  description_html?: string;
  priority: string;
  state: string | { id: string; name: string };
  parent: string | null;
};
type Relation = { issue_id: string };
type Relations = { blocked_by?: Relation[] };

const APPLY = process.argv.includes("--apply");
const MANIFEST_ONLY = process.argv.includes("--manifest-only");
const API_BASE = process.env.PLANE_API_BASE_URL;
const WORKSPACE = process.env.PLANE_WORKSPACE_SLUG;
const TOKEN = process.env.PLANE_API_TOKEN;
const configuredRequestInterval = Number(
  process.env.PLANE_REQUEST_INTERVAL_MS ?? "1050",
);
if (
  !Number.isFinite(configuredRequestInterval) ||
  configuredRequestInterval < 250
) {
  fail("PLANE_REQUEST_INTERVAL_MS must be a finite number of at least 250");
}
const REQUEST_INTERVAL_MS = configuredRequestInterval;
let nextRequestAt = 0;

function fail(message: string): never {
  throw new Error(message);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function paragraph(value: string): string {
  return `<p>${escapeHtml(value)}</p>`;
}

function list(values: string[]): string {
  return `<ul>${values.map((value) => `<li>${escapeHtml(value)}</li>`).join("")}</ul>`;
}

function managedSpecDigest(spec: WorkItemSpec): string {
  const { state: _initialState, ...managedSpec } = spec;
  return createHash("sha256").update(JSON.stringify(managedSpec)).digest("hex");
}

function managedKeyMarker(key: string): string {
  return `<code>${escapeHtml(key)}</code>`;
}

function managedDigestMarker(spec: WorkItemSpec): string {
  return `<code>sha256:${managedSpecDigest(spec)}</code>`;
}

function renderDescription(spec: WorkItemSpec): string {
  const related = spec.related.length
    ? `<h2>Related inputs</h2><ul>${spec.related
        .map(
          (url) =>
            `<li><a href="${escapeHtml(url)}">${escapeHtml(url)}</a></li>`,
        )
        .join("")}</ul>`
    : "";
  return [
    `<p><strong>Managed key:</strong> <code>${escapeHtml(spec.key)}</code></p>`,
    `<p><strong>Managed spec digest:</strong> ${managedDigestMarker(spec)}</p>`,
    "<h2>Outcome</h2>",
    paragraph(spec.outcome),
    "<h2>User journey</h2>",
    paragraph(spec.journey),
    "<h2>Scope</h2>",
    list(spec.scope),
    "<h2>Acceptance</h2>",
    list(spec.acceptance),
    "<h2>Non-goals</h2>",
    list(spec.non_goals),
    "<h2>Evidence required</h2>",
    list(spec.evidence),
    related,
    "<p><em>Until a reviewed release establishes a different source, <code>plane/v0-backlog.json</code> in the Open Work Commons repository is canonical for this specification. Plane owns status, assignee, dates, discussion, and execution evidence.</em></p>",
  ].join("");
}

function validateManifest(manifest: Manifest): void {
  if (manifest.schema_version !== 1)
    fail(`Unsupported manifest schema ${manifest.schema_version}`);
  const keys = new Set(manifest.work_items.map((item) => item.key));
  if (keys.size !== manifest.work_items.length) {
    fail("Duplicate managed keys in manifest");
  }
  const titles = new Set(manifest.work_items.map((item) => item.title));
  if (titles.size !== manifest.work_items.length) {
    fail("Duplicate work-item titles in manifest");
  }
  const positions = new Map(
    manifest.work_items.map((spec, index) => [spec.key, index]),
  );
  const byKey = new Map(manifest.work_items.map((spec) => [spec.key, spec]));
  for (const spec of manifest.work_items) {
    if (spec.parent && !keys.has(spec.parent)) {
      fail(`${spec.key}: unknown parent ${spec.parent}`);
    }
    if (spec.parent === spec.key) fail(`${spec.key}: cannot parent itself`);
    if (
      spec.parent &&
      (positions.get(spec.parent) ?? Number.POSITIVE_INFINITY) >=
        (positions.get(spec.key) ?? -1)
    ) {
      fail(`${spec.key}: parent ${spec.parent} must appear first`);
    }
    if (new Set(spec.blocked_by).size !== spec.blocked_by.length) {
      fail(`${spec.key}: duplicate blocker`);
    }
    for (const blocker of spec.blocked_by) {
      if (!keys.has(blocker)) fail(`${spec.key}: unknown blocker ${blocker}`);
      if (blocker === spec.key) fail(`${spec.key}: cannot block itself`);
    }
  }
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (key: string): void => {
    if (visiting.has(key)) fail(`${key}: blocked-by cycle in manifest`);
    if (visited.has(key)) return;
    visiting.add(key);
    for (const blocker of byKey.get(key)?.blocked_by ?? []) visit(blocker);
    visiting.delete(key);
    visited.add(key);
  };
  for (const key of keys) visit(key);
}

function resolveWorkItem(
  workItems: WorkItem[],
  spec: WorkItemSpec,
): WorkItem | undefined {
  const keyMatches = workItems.filter((item) =>
    item.description_html?.includes(managedKeyMarker(spec.key)),
  );
  if (keyMatches.length > 1) fail(`${spec.key}: duplicate managed-key matches`);
  if (keyMatches[0]) return keyMatches[0];
  const titleMatches = workItems.filter((item) => item.name === spec.title);
  if (titleMatches.length > 1)
    fail(`${spec.key}: duplicate exact title matches`);
  return titleMatches[0];
}

function staticDrift(
  spec: WorkItemSpec,
  item: WorkItem,
  state: State,
  resolved: ReadonlyMap<string, WorkItem>,
  includeInitialState = false,
): string[] {
  const drift: string[] = [];
  if (item.name !== spec.title) drift.push("title");
  if (item.priority !== spec.priority) drift.push("priority");
  if (includeInitialState && stateId(item) !== state.id)
    drift.push("initial-state");
  const expectedParent = spec.parent ? resolved.get(spec.parent)?.id : null;
  if (spec.parent && expectedParent === undefined)
    drift.push("parent-unresolved");
  else if (item.parent !== expectedParent) drift.push("parent");
  if (!item.description_html?.includes(managedKeyMarker(spec.key))) {
    drift.push("managed-key");
  }
  if (!item.description_html?.includes(managedDigestMarker(spec))) {
    drift.push("managed-spec-digest");
  }
  if (item.description_html !== renderDescription(spec)) {
    drift.push("managed-description");
  }
  return drift;
}

async function waitForSlot(): Promise<void> {
  const now = Date.now();
  if (now < nextRequestAt) {
    await new Promise((resolve) => setTimeout(resolve, nextRequestAt - now));
  }
  nextRequestAt = Date.now() + REQUEST_INTERVAL_MS;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  if (!TOKEN) fail("PLANE_API_TOKEN is required");
  if (!API_BASE) fail("PLANE_API_BASE_URL is required");
  await waitForSlot();
  const method = (init.method ?? "GET").toUpperCase();
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": TOKEN,
      ...init.headers,
    },
  });
  if (!response.ok) {
    fail(
      `Plane API ${method} ${path} failed with ${response.status}; no automatic retry was attempted`,
    );
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function listAll<T>(path: string): Promise<T[]> {
  const results: T[] = [];
  let cursor: string | undefined;
  do {
    const separator = path.includes("?") ? "&" : "?";
    const page = await request<
      T[] | { results?: T[]; next_page_results?: boolean; next_cursor?: string }
    >(
      `${path}${separator}per_page=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
    );
    if (Array.isArray(page)) return page;
    results.push(...(page.results ?? []));
    cursor = page.next_page_results ? page.next_cursor : undefined;
  } while (cursor);
  return results;
}

function stateId(item: WorkItem): string {
  return typeof item.state === "string" ? item.state : item.state.id;
}

async function main(): Promise<void> {
  const manifest = JSON.parse(
    await readFile(
      new URL("../../plane/v0-backlog.json", import.meta.url),
      "utf8",
    ),
  ) as Manifest;
  validateManifest(manifest);
  if (MANIFEST_ONLY) {
    console.log(
      JSON.stringify(
        {
          mode: "manifest-only",
          project: manifest.project.identifier,
          work_items: manifest.work_items.length,
          relations: manifest.work_items.reduce(
            (total, item) => total + item.blocked_by.length,
            0,
          ),
        },
        null,
        2,
      ),
    );
    return;
  }
  if (!WORKSPACE) fail("PLANE_WORKSPACE_SLUG is required");
  if (!API_BASE) fail("PLANE_API_BASE_URL is required");
  const webBase = process.env.PLANE_WEB_BASE_URL ?? new URL(API_BASE).origin;

  const projects = await listAll<Project>(
    `/workspaces/${encodeURIComponent(WORKSPACE)}/projects/`,
  );
  const projectMatches = projects.filter(
    (project) =>
      project.identifier === manifest.project.identifier ||
      project.name === manifest.project.name,
  );
  if (projectMatches.length !== 1)
    fail(
      `Expected one exact ${manifest.project.identifier} project; found ${projectMatches.length}`,
    );
  const project = projectMatches[0];
  if (!project) fail("Resolved project disappeared");
  if (
    project.identifier !== manifest.project.identifier ||
    project.name !== manifest.project.name
  ) {
    fail("Project identifier/name mismatch");
  }

  const projectBase = `/workspaces/${encodeURIComponent(WORKSPACE)}/projects/${project.id}`;
  const states = await listAll<State>(`${projectBase}/states/`);
  const statesByName = new Map(states.map((state) => [state.name, state]));
  for (const spec of manifest.work_items) {
    if (!statesByName.has(spec.state))
      fail(`${spec.key}: missing Plane state ${spec.state}`);
  }

  let workItems = await listAll<WorkItem>(
    `${projectBase}/work-items/?expand=state`,
  );
  const resolved = new Map<string, WorkItem>();
  const pending: WorkItemSpec[] = [];
  for (const spec of manifest.work_items) {
    const match = resolveWorkItem(workItems, spec);
    if (match) resolved.set(spec.key, match);
    else pending.push(spec);
  }

  if (!APPLY) {
    const drift: Array<{ key: string; fields: string[] }> = [];
    for (const spec of manifest.work_items) {
      const listed = resolved.get(spec.key);
      const state = statesByName.get(spec.state);
      if (!listed || !state) continue;
      const item = await request<WorkItem>(
        `${projectBase}/work-items/${listed.id}/`,
      );
      const fields = staticDrift(spec, item, state, resolved);
      const expectedBlockers = spec.blocked_by
        .map((key) => resolved.get(key)?.id)
        .filter((id): id is string => id !== undefined);
      if (expectedBlockers.length !== spec.blocked_by.length) {
        fields.push("blocked-by-unresolved");
      } else {
        const relations = await request<Relations>(
          `${projectBase}/work-items/${item.id}/relations/`,
        );
        const actualBlockers = new Set(
          (relations.blocked_by ?? []).map((relation) => relation.issue_id),
        );
        if (
          actualBlockers.size !== expectedBlockers.length ||
          expectedBlockers.some((id) => !actualBlockers.has(id))
        ) {
          fields.push("blocked-by");
        }
      }
      if (fields.length) drift.push({ key: spec.key, fields });
    }
    console.log(
      JSON.stringify(
        {
          mode: "check",
          project: project.identifier,
          existing: resolved.size,
          missing: pending.map((item) => item.key),
          drift,
        },
        null,
        2,
      ),
    );
    if (pending.length || drift.length) process.exitCode = 2;
    return;
  }

  const createdIds = new Set<string>();
  for (const spec of manifest.work_items) {
    const listed = resolved.get(spec.key);
    const state = statesByName.get(spec.state);
    if (!listed || !state) continue;
    const item = await request<WorkItem>(
      `${projectBase}/work-items/${listed.id}/`,
    );
    const drift = staticDrift(spec, item, state, resolved);
    if (drift.length) {
      fail(
        `${spec.key}: existing managed fields drifted (${drift.join(", ")}); refusing mutation`,
      );
    }
  }

  for (const spec of manifest.work_items) {
    if (resolved.has(spec.key)) continue;
    if (spec.parent && !resolved.has(spec.parent))
      fail(`${spec.key}: parent ${spec.parent} has not been created`);
    workItems = await listAll<WorkItem>(
      `${projectBase}/work-items/?expand=state`,
    );
    const nowMatch = resolveWorkItem(workItems, spec);
    if (nowMatch) {
      resolved.set(spec.key, nowMatch);
      continue;
    }
    const state = statesByName.get(spec.state);
    if (!state) fail(`${spec.key}: state disappeared`);
    const created = await request<WorkItem>(`${projectBase}/work-items/`, {
      method: "POST",
      body: JSON.stringify({
        name: spec.title,
        description_html: renderDescription(spec),
        priority: spec.priority,
        state: state.id,
        parent: spec.parent ? resolved.get(spec.parent)?.id : null,
      }),
    });
    resolved.set(spec.key, created);
    createdIds.add(created.id);
    console.log(
      `created ${project.identifier}-${created.sequence_id} ${spec.key}`,
    );
  }

  for (const spec of manifest.work_items) {
    const item = resolved.get(spec.key);
    if (!item) fail(`${spec.key}: unresolved after create`);
    const expected = spec.blocked_by.map(
      (key) =>
        resolved.get(key)?.id ?? fail(`${spec.key}: unresolved blocker ${key}`),
    );
    const relations = await request<Relations>(
      `${projectBase}/work-items/${item.id}/relations/`,
    );
    const actual = (relations.blocked_by ?? []).map(
      (relation) => relation.issue_id,
    );
    const unexpected = actual.filter((id) => !expected.includes(id));
    if (unexpected.length)
      fail(
        `${spec.key}: unexpected existing blocked_by relations; refusing removal`,
      );
    const missing = expected.filter((id) => !actual.includes(id));
    if (missing.length) {
      await request(`${projectBase}/work-items/${item.id}/relations/`, {
        method: "POST",
        body: JSON.stringify({ relation_type: "blocked_by", issues: missing }),
      });
      console.log(`linked ${spec.key} to ${missing.length} blocker(s)`);
    }
  }

  workItems = await listAll<WorkItem>(
    `${projectBase}/work-items/?expand=state`,
  );
  const links: string[] = [];
  for (const spec of manifest.work_items) {
    const listed = resolveWorkItem(workItems, spec);
    if (!listed) fail(`${spec.key}: missing during verification`);
    const item = await request<WorkItem>(
      `${projectBase}/work-items/${listed.id}/`,
    );
    if (!item) fail(`${spec.key}: missing during verification`);
    const state = statesByName.get(spec.state);
    if (!state) fail(`${spec.key}: state disappeared during verification`);
    const drift = staticDrift(
      spec,
      item,
      state,
      resolved,
      createdIds.has(item.id),
    );
    if (drift.length)
      fail(
        `${spec.key}: managed-field verification failed (${drift.join(", ")})`,
      );
    const relations = await request<Relations>(
      `${projectBase}/work-items/${item.id}/relations/`,
    );
    const actualBlockers = new Set(
      (relations.blocked_by ?? []).map((relation) => relation.issue_id),
    );
    const expectedBlockers = spec.blocked_by.map(
      (key) =>
        resolved.get(key)?.id ?? fail(`${spec.key}: missing blocker ${key}`),
    );
    if (
      actualBlockers.size !== expectedBlockers.length ||
      expectedBlockers.some((id) => !actualBlockers.has(id))
    ) {
      fail(`${spec.key}: dependency verification failed`);
    }
    links.push(
      `${webBase}/${WORKSPACE}/browse/${project.identifier}-${item.sequence_id}`,
    );
  }
  console.log(
    JSON.stringify({ mode: "apply", verified: links.length, links }, null, 2),
  );
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
