#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(join(root, "apps/wallet-api/package.json"));
const { neon } = require("@neondatabase/serverless");
let failed = false;

function fail(message) {
  console.error(`::error::${message}`);
  failed = true;
}

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

function sourceFor(name, file) {
  if (file) {
    const abs = file.startsWith("/") ? file : join(root, file);
    if (!existsSync(abs)) {
      fail(`${name}: env file missing: ${file}`);
      return {};
    }
    return parseEnvFile(abs);
  }
  return process.env;
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

function assertDbUrl(name, env) {
  const value = env.DATABASE_URL;
  if (!value) {
    fail(`${name}: DATABASE_URL missing`);
    return null;
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    fail(`${name}: DATABASE_URL is not a valid URL`);
    return null;
  }
  if (!["postgres:", "postgresql:"].includes(url.protocol)) {
    fail(`${name}: DATABASE_URL is not Postgres`);
    return null;
  }
  if (["localhost", "127.0.0.1", "::1"].includes(url.hostname)) {
    fail(`${name}: DATABASE_URL points to local host`);
    return null;
  }
  if (/\\n|[\r\n]/.test(value)) {
    fail(`${name}: DATABASE_URL contains newline escape characters`);
    return null;
  }
  return value;
}

async function ensureTenantSchema(db) {
  await db`
    create table if not exists benzo_tenant_documents (
      app text not null,
      tenant_key text not null,
      version integer not null default 1,
      ciphertext text not null,
      updated_at timestamptz not null default now(),
      primary key (app, tenant_key)
    )
  `;
  await db`
    create table if not exists benzo_tenant_routes (
      app text not null,
      route_type text not null,
      route_hash text not null,
      tenant_key text not null,
      expires_at bigint,
      created_at timestamptz not null default now(),
      primary key (app, route_type, route_hash)
    )
  `;
  await db`
    create table if not exists benzo_request_limits (
      app text not null,
      tenant_key text not null,
      bucket text not null,
      window_start bigint not null,
      count integer not null,
      updated_at timestamptz not null default now(),
      primary key (app, tenant_key, bucket)
    )
  `;
  await db`
    create index if not exists benzo_request_limits_window_start_idx
    on benzo_request_limits (window_start)
  `;
}

async function ensureRelayerSchema(db) {
  await db`
    create table if not exists benzo_relayer_abuse (
      kind text not null,
      key text not null,
      tokens double precision,
      last_ms bigint,
      count integer,
      code integer,
      body jsonb,
      updated_at timestamptz not null default now(),
      primary key (kind, key)
    )
  `;
}

async function tableExists(db, table) {
  const rows = await db`select to_regclass(${table}) as table_name`;
  return Boolean(rows[0]?.table_name);
}

async function auditOne(name, env) {
  const url = assertDbUrl(name, env);
  if (!url) return;
  if (!env.BENZO_DATA_ENCRYPTION_SECRET) fail(`${name}: BENZO_DATA_ENCRYPTION_SECRET missing`);
  const host = new URL(url).hostname;
  const db = neon(url);
  const versionRows = await db`select version() as version`;
  const version = String(versionRows[0]?.version ?? "");
  if (!/postgres/i.test(version)) fail(`${name}: database did not report PostgreSQL`);
  await ensureTenantSchema(db);
  await ensureRelayerSchema(db);
  const requiredTables = [
    "benzo_tenant_documents",
    "benzo_tenant_routes",
    "benzo_request_limits",
    "benzo_relayer_abuse",
  ];
  for (const table of requiredTables) {
    if (!(await tableExists(db, table))) fail(`${name}: ${table} missing after schema init`);
  }
  const provider = host.endsWith(".neon.tech") ? "neon" : "postgres";
  console.log(`[prod-db] ${name}: reachable ${provider} host, schema tables verified`);
}

const args = parseArgs();
const targets = [
  ["wallet", sourceFor("wallet", args.get("wallet"))],
  ["console", sourceFor("console", args.get("console"))],
];

for (const [name, env] of targets) {
  try {
    await auditOne(name, env);
  } catch (error) {
    const code = typeof error?.code === "string" ? ` (${error.code})` : "";
    fail(`${name}: database audit failed${code}`);
  }
}

if (failed) process.exit(1);
console.log("[prod-db] production Postgres wiring verified without printing secrets");
