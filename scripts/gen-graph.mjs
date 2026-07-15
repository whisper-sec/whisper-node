// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Generate the `graph` catalog tables in index.js and the typed method surface in
// index.d.ts from the Whisper query catalog (the single source of truth). Reads
// sdk-methods.json (method name, mode, cypher/flow slug, params, docs URL) and
// catalog.json (inputs, flow knobs, purpose/why prose), both index-aligned, and
// rewrites the marked regions in place - so the SDK can never drift from the catalog.
//
// Run:  node scripts/gen-graph.mjs [path-to-whisper-catalog]
// Default catalog path is ../whisper-catalog relative to this repo.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const catalogDir = resolve(process.argv[2] ?? join(repoRoot, "..", "whisper-catalog"));

const sdk = JSON.parse(readFileSync(join(catalogDir, "sdk-methods.json"), "utf8"));
const catalog = JSON.parse(readFileSync(join(catalogDir, "catalog.json"), "utf8"));

if (sdk.methods.length !== catalog.entries.length) {
  throw new Error(`method/entry count mismatch: ${sdk.methods.length} vs ${catalog.entries.length}`);
}

const docsBase = String(sdk.docsBase || catalog.graph.docsBase || "https://www.whisper.security").replace(/\/+$/, "");
const flowRunUrl = String((sdk.flowRun && sdk.flowRun.endpoint) || catalog.graph.flowRun.endpoint);

// camelCase a kebab-case catalog id, the same mapping sdk-methods.json uses.
function camel(id) {
  return String(id)
    .split("-")
    .map((w, i) => (i === 0 ? w : w.charAt(0).toUpperCase() + w.slice(1)))
    .join("");
}

// Plain ASCII only (no em-dashes anywhere): normalise any typography that slipped into
// the catalog prose, and never emit a "*/" that could break a JSDoc block.
function clean(s) {
  return String(s ?? "")
    .replace(/\u2014/g, ", ")           // em dash -> comma
    .replace(/\u2013/g, "-")            // en dash -> hyphen
    .replace(/[\u2018\u2019]/g, "'")    // single curly quotes -> straight '
    .replace(/[\u201c\u201d]/g, '"')    // double curly quotes -> straight "
    .replace(/\u2026/g, "...")          // ellipsis -> ...
    .replace(/\u00a0/g, " ")            // non-breaking space -> normal space
    .replace(/\u2192/g, "->")           // arrow
    .replace(/\*\//g, "* /")
    .trim();
}

function jsString(s) {
  return JSON.stringify(String(s));
}

// Wrap prose to a width so the generated doc comments stay readable.
function wrap(text, width) {
  const words = text.split(/\s+/);
  const out = [];
  let line = "";
  for (const w of words) {
    if (line === "") line = w;
    else if ((line + " " + w).length <= width) line += " " + w;
    else {
      out.push(line);
      line = w;
    }
  }
  if (line) out.push(line);
  return out;
}

function docsPath(m) {
  const url = String(m.docsUrl || docsBase + m.docPath);
  if (!url.startsWith(docsBase + "/")) throw new Error(`${m.method}: docs URL ${url} is not under ${docsBase}`);
  return url.slice(docsBase.length);
}

// ── Build one model row per catalog entry ────────────────────────────────────────────
const rows = sdk.methods.map((m, i) => {
  const entry = catalog.entries[i];
  if (camel(entry.id) !== m.method) throw new Error(`entry/method misaligned at ${i}: ${entry.id} vs ${m.method}`);
  const inputs = entry.inputs || [];
  const docs = docsPath(m);
  const base = {
    name: m.method,
    id: entry.id,
    docs,
    // Two-tier access, straight from the catalog: requiresKey:false marks the direct
    // read verbs that run with no key at all (a rate-limited taste, real answers).
    keyless: !(m.requiresKey ?? true),
    purpose: clean(entry.purpose || m.summary || m.method),
    why: clean(entry.why || ""),
    returns: (m.returns || []).map(clean),
  };
  if (m.mode === "flow") {
    return {
      ...base,
      mode: "flow",
      slug: m.flowRun && m.flowRun.bodyShape ? m.flowRun.bodyShape.slug : entry.id,
      primary: inputs.length ? inputs[0].paramName : null,
      inputs: inputs.map((x) => x.paramName),
      params: (entry.params || []).map((p) => p.name),
    };
  }
  if (!m.cypher) throw new Error(`${m.method}: direct entry without a Cypher`);
  const proc = /^CALL\s+([A-Za-z0-9_.]+)\s*\(/.exec(m.cypher);
  if (inputs.length > 1) {
    // The map-call form (whisper.submit): every catalog input becomes an optional field of
    // one Cypher map, each value bound as its own $-parameter. The first select field (the
    // kind discriminator) is required; the server validates the rest per kind.
    if (!proc) throw new Error(`${m.method}: cannot derive the procedure name from ${m.cypher}`);
    return {
      ...base,
      mode: "direct",
      proc: proc[1],
      fields: inputs.map((x) => [x.id, x.paramName]),
      requires: [inputs[0].paramName],
    };
  }
  return {
    ...base,
    mode: "direct",
    cypher: clean(m.cypher),
    input: inputs.length ? inputs[0].paramName : null,
  };
});

const flows = rows.filter((r) => r.mode === "flow");
const directs = rows.filter((r) => r.mode === "direct");
if (directs.length !== 14 || flows.length !== 15) {
  throw new Error(`unexpected catalog split: ${directs.length} direct + ${flows.length} flow`);
}
const keyless = rows.filter((r) => r.keyless);
if (keyless.length !== 13 || keyless.some((r) => r.mode !== "direct")) {
  throw new Error(`unexpected keyless set: ${keyless.length} keyless (expected the 13 direct reads)`);
}

// ── index.js: the runtime catalog table ──────────────────────────────────────────────
function jsRow(r) {
  const docs = `GRAPH_DOCS_BASE + ${jsString(r.docs)}`;
  const keyless = `keyless: ${r.keyless ? "true" : "false"}`;
  const summary = `summary: ${jsString(r.purpose)}`;
  if (r.mode === "flow") {
    const parts = [
      `name: ${jsString(r.name)}`,
      `mode: "flow"`,
      keyless,
      `slug: ${jsString(r.slug)}`,
      `primary: ${r.primary ? jsString(r.primary) : "null"}`,
      `inputs: [${r.inputs.map(jsString).join(", ")}]`,
      `params: [${r.params.map(jsString).join(", ")}]`,
      summary,
      `docs: ${docs}`,
    ];
    return `  { ${parts.join(", ")} },`;
  }
  if (r.fields) {
    const fields = r.fields.map(([id, p]) => `[${jsString(id)}, ${jsString(p)}]`).join(", ");
    return `  { name: ${jsString(r.name)}, mode: "direct", ${keyless}, proc: ${jsString(r.proc)}, fields: [${fields}], requires: [${r.requires.map(jsString).join(", ")}], ${summary}, docs: ${docs} },`;
  }
  return `  { name: ${jsString(r.name)}, mode: "direct", ${keyless}, input: ${r.input ? jsString(r.input) : "null"}, cypher: ${jsString(r.cypher)}, ${summary}, docs: ${docs} },`;
}

const jsRegion = [
  "// The Whisper query catalog, one row per entry (14 direct + 15 flow), in catalog order.",
  "// A direct row carries its catalog Cypher (input bound as a $-parameter); a flow row",
  "// carries its gallery/run slug plus the input/param names the workflow runner accepts;",
  "// the map-call row (submit) enumerates its fields. `keyless` marks the 13 direct read",
  "// verbs that run with no key at all (two-tier, straight from the catalog's requiresKey);",
  "// `summary` feeds recipes() discovery; `docs` is the canonical docs URL.",
  `const GRAPH_DOCS_BASE = ${jsString(docsBase)};`,
  `const GRAPH_FLOW_RUN_URL = ${jsString(flowRunUrl)};`,
  "const GRAPH_METHODS = [",
  ...rows.map(jsRow),
  "];",
].join("\n");

// ── index.d.ts: the typed method surface with docs links ────────────────────────────
function dtsDoc(r) {
  const lines = [r.purpose];
  if (r.why && r.why !== r.purpose) {
    lines.push("");
    lines.push(...wrap(r.why, 92));
  }
  lines.push("");
  if (r.mode === "flow") {
    lines.push(`KEYED flow: streams Server-Sent Events from the workflow runner (slug "${r.slug}")`);
    lines.push("and resolves to the collected { slug, steps, complete, events }.");
    if (r.inputs.length) lines.push(`Inputs: ${r.inputs.join(", ")}.${r.params.length ? ` Params: ${r.params.join(", ")}.` : ""}`);
  } else if (r.fields) {
    lines.push(`KEYED write: CALL ${r.proc}({...}) with the payload fields bound as $-parameters.`);
    lines.push(`Fields: ${r.fields.map(([, p]) => p).join(", ")} (${r.requires.join(", ")} required).`);
  } else if (r.keyless) {
    lines.push("KEYLESS direct read: runs with NO key at all (a rate-limited taste, real");
    lines.push("answers); pass a key ({ apiKey } or WHISPER_API_KEY) to lift the limit.");
    lines.push(`Cypher: ${r.cypher}`);
  } else {
    lines.push(`KEYED. Cypher: ${r.cypher}`);
  }
  if (r.returns.length && r.mode !== "flow") lines.push(`Returns columns: ${r.returns.join(", ")}.`);
  lines.push(`@see ${docsBase}${r.docs}`);
  const body = lines.map((l) => (l === "" ? "   *" : `   * ${l}`)).join("\n");
  return `  /**\n${body}\n   */`;
}

function dtsSig(r) {
  if (r.mode === "flow") return `  ${r.name}(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;`;
  if (r.fields) return `  ${r.name}(payload: GraphSubmission, opts?: GraphOptions): Promise<GraphResult>;`;
  if (!r.input) return `  ${r.name}(opts?: GraphOptions): Promise<GraphResult>;`;
  return `  ${r.name}(value: string, opts?: GraphOptions): Promise<GraphResult>;`;
}

const dtsRegion = rows.map((r) => `${dtsDoc(r)}\n${dtsSig(r)}`).join("\n\n");

// ── Splice the marked regions in place ───────────────────────────────────────────────
const BEGIN = "BEGIN GENERATED: graph catalog (scripts/gen-graph.mjs) - do not edit by hand";
const END = "END GENERATED: graph catalog";

function splice(path, replacement) {
  const src = readFileSync(path, "utf8");
  const lines = src.split("\n");
  const a = lines.findIndex((l) => l.includes(BEGIN));
  const b = lines.findIndex((l) => l.includes(END));
  if (a === -1 || b === -1 || b <= a) throw new Error(`${path}: generated-region markers not found`);
  const out = [...lines.slice(0, a + 1), replacement, ...lines.slice(b)].join("\n");
  if (/\u2014/.test(out)) throw new Error(`${path}: an em-dash slipped into the output`);
  writeFileSync(path, out);
}

splice(join(repoRoot, "index.js"), jsRegion);
splice(join(repoRoot, "index.d.ts"), dtsRegion);
console.log(`graph catalog: ${rows.length} methods (${directs.length} direct, ${flows.length} flow) -> index.js + index.d.ts`);
