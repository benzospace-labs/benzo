#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(join(root, "apps/wallet-api/package.json"));
const { neon } = require("@neondatabase/serverless");

function parseEnvFile(file) {
  const out = {};
  const src = readFileSync(file, "utf8");
  for (const line of src.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx <= 0) continue;
    const key = trimmed.slice(0, idx);
    let value = trimmed.slice(idx + 1);
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

function parseArgs() {
  const args = new Map();
  for (const raw of process.argv.slice(2)) {
    const [k, ...rest] = raw.split("=");
    if (!k || rest.length === 0) continue;
    args.set(k, rest.join("="));
  }
  return args;
}

function sourceFor(name, file) {
  if (file) {
    const abs = file.startsWith("/") ? file : join(root, file);
    if (!existsSync(abs)) {
      console.error(`::error::${name}: env file missing: ${file}`);
      return {};
    }
    return parseEnvFile(abs);
  }
  return process.env;
}

const args = parseArgs();
const customHorizon = Number(process.env.BENZO_REQUEST_LIMIT_RETENTION_SECONDS);
const horizonSeconds = Number.isFinite(customHorizon) && customHorizon > 0 ? customHorizon : 7 * 24 * 60 * 60;

async function pruneDb(name, env) {
  const url = env.DATABASE_URL;
  if (!url) {
    console.log(`[prune-limits] ${name}: DATABASE_URL unset, skipping`);
    return 0;
  }
  const db = neon(url);
  const cutoff = Math.floor(Date.now() / 1000) - Math.max(horizonSeconds, 60);
  const rows = await db`
    delete from benzo_request_limits
    where window_start < ${cutoff}
    returning 1
  `;
  const count = rows.length;
  console.log(`[prune-limits] ${name}: deleted ${count} rows older than ${horizonSeconds}s`);
  return count;
}

const targets = [
  ["wallet", sourceFor("wallet", args.get("wallet"))],
  ["console", sourceFor("console", args.get("console"))],
];

let total = 0;
for (const [name, env] of targets) {
  total += await pruneDb(name, env);
}
console.log(`[prune-limits] retention sweep complete (total pruned: ${total})`);
