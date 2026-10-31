#!/usr/bin/env node
/**
 * Online SQLite Backup, Integrity Verification & Atomic Restore Tooling for REA Cloud Studio.
 *
 * Uses SQLite's native `VACUUM INTO` snapshot command so live WAL readers/writers are
 * never corrupted by naive file-copy races across `studio.sqlite` + `-wal` + `-shm`.
 *
 * CLI usage:
 *   node studio/scripts/sqliteBackup.mjs backup  [sourceSqlitePath] [destBackupPath]
 *   node studio/scripts/sqliteBackup.mjs verify  <backupSqlitePath>
 *   node studio/scripts/sqliteBackup.mjs restore <backupSqlitePath> [targetSqlitePath]
 */

import {
  chmodSync,
  existsSync,
  mkdirSync,
  renameSync,
  rmSync,
  statSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

const REQUIRED_TABLES = [
  "meta",
  "tenants",
  "api_keys",
  "sessions",
  "billing_events",
  "payment_intents",
  "consumed_tx_hashes",
  "processed_webhook_ids",
  "license_activations",
];

function escapeSqliteStringLiteral(value) {
  const s = String(value);
  if (s.includes("\0")) {
    throw new Error("Invalid NUL byte in SQLite file path.");
  }
  return `'${s.replaceAll("'", "''")}'`;
}

export function defaultStudioSqlitePath(env = process.env) {
  const dataDir = resolve(env.REA_STUDIO_DATA_DIR || "/data");
  return join(dataDir, "studio.sqlite");
}

/**
 * Verifies a SQLite backup file for page-level integrity, foreign-key consistency,
 * and required Studio billing/replay-protection tables.
 */
export function verifySqliteBackup(backupPath) {
  const resolved = resolve(backupPath);
  if (!existsSync(resolved)) {
    throw new Error(`SQLite backup file does not exist: ${resolved}`);
  }
  const st = statSync(resolved);
  if (!st.isFile() || st.size === 0) {
    throw new Error(`SQLite backup path is empty or not a regular file: ${resolved}`);
  }

  const db = new DatabaseSync(resolved, { readOnly: true });
  try {
    const integrityRows = db.prepare("PRAGMA integrity_check").all();
    const integrityResult = integrityRows.map((r) => Object.values(r)[0]).join("; ");
    if (integrityResult !== "ok") {
      throw new Error(`SQLite integrity_check failed: ${integrityResult}`);
    }

    const fkRows = db.prepare("PRAGMA foreign_key_check").all();
    if (fkRows.length > 0) {
      throw new Error(`SQLite foreign_key_check reported ${fkRows.length} violation(s).`);
    }

    const existingTables = new Set(
      db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .all()
        .map((r) => String(r.name)),
    );
    const missingTables = REQUIRED_TABLES.filter((t) => !existingTables.has(t));
    if (missingTables.length > 0) {
      throw new Error(
        `SQLite backup is missing required Studio schema tables: ${missingTables.join(", ")}`,
      );
    }

    const counts = {};
    for (const table of REQUIRED_TABLES) {
      const row = db.prepare(`SELECT COUNT(*) AS cnt FROM ${table}`).get();
      counts[table] = Number(row?.cnt || 0);
    }

    return {
      ok: true,
      path: resolved,
      bytes: st.size,
      integrity: "ok",
      counts,
    };
  } finally {
    db.close();
  }
}

/**
 * Creates an atomic, consistent point-in-time snapshot of an active WAL database
 * using `VACUUM INTO` and verifies the resulting snapshot before finalizing.
 */
export function backupSqliteDatabase(sourceSqlitePath, destBackupPath) {
  const src = resolve(sourceSqlitePath);
  const dst = resolve(destBackupPath);
  if (!existsSync(src)) {
    throw new Error(`Source SQLite database not found: ${src}`);
  }
  if (src === dst) {
    throw new Error("Destination backup path must differ from source SQLite path.");
  }

  const outDir = dirname(dst);
  mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const stagePath = `${dst}.tmp.${process.pid}.${Date.now()}`;
  rmSync(stagePath, { force: true });

  const db = new DatabaseSync(src);
  try {
    db.exec("PRAGMA busy_timeout = 5000;");
    db.exec("PRAGMA wal_checkpoint(PASSIVE);");
    db.exec(`VACUUM INTO ${escapeSqliteStringLiteral(stagePath)};`);
  } catch (err) {
    rmSync(stagePath, { force: true });
    throw err;
  } finally {
    db.close();
  }

  try {
    chmodSync(stagePath, 0o600);
    const verification = verifySqliteBackup(stagePath);
    renameSync(stagePath, dst);
    chmodSync(dst, 0o600);
    return {
      ...verification,
      source: src,
      path: dst,
      bytes: statSync(dst).size,
    };
  } catch (err) {
    rmSync(stagePath, { force: true });
    throw err;
  }
}

/**
 * Restores a verified SQLite backup to `targetSqlitePath` atomically.
 * NOTE: Stop the running Studio server before restoring so open WAL descriptors
 * do not overwrite the restored file.
 */
export function restoreSqliteDatabase(backupPath, targetSqlitePath) {
  const src = resolve(backupPath);
  const dst = resolve(targetSqlitePath);
  if (src === dst) {
    throw new Error("Backup path and target SQLite path must differ.");
  }

  const verifiedBackup = verifySqliteBackup(src);
  const dstDir = dirname(dst);
  mkdirSync(dstDir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dstDir, 0o700);
  } catch {
    // Best-effort on filesystems without POSIX mode bits.
  }

  const stagePath = `${dst}.restore.${process.pid}.${Date.now()}`;
  rmSync(stagePath, { force: true });

  const srcDb = new DatabaseSync(src, { readOnly: true });
  try {
    srcDb.exec(`VACUUM INTO ${escapeSqliteStringLiteral(stagePath)};`);
  } catch (err) {
    rmSync(stagePath, { force: true });
    throw err;
  } finally {
    srcDb.close();
  }

  chmodSync(stagePath, 0o600);
  verifySqliteBackup(stagePath);

  let preRestoreBackupPath = null;
  if (existsSync(dst)) {
    preRestoreBackupPath = `${dst}.pre-restore.bak`;
    backupSqliteDatabase(dst, preRestoreBackupPath);
  }

  // Remove any stale WAL/SHM sidecars before swapping in the clean compacted database.
  rmSync(`${dst}-wal`, { force: true });
  rmSync(`${dst}-shm`, { force: true });
  renameSync(stagePath, dst);
  chmodSync(dst, 0o600);

  const postCheck = verifySqliteBackup(dst);
  return {
    ...postCheck,
    restored_from: verifiedBackup.path,
    pre_restore_backup: preRestoreBackupPath,
  };
}

function runCli() {
  const [cmd, arg1, arg2] = process.argv.slice(2);
  if (cmd === "backup") {
    const src = arg1 || defaultStudioSqlitePath();
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const dst = arg2 || `${src}.backup-${stamp}.sqlite`;
    const result = backupSqliteDatabase(src, dst);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  if (cmd === "verify") {
    if (!arg1) {
      throw new Error("Usage: sqliteBackup.mjs verify <backupSqlitePath>");
    }
    const result = verifySqliteBackup(arg1);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  if (cmd === "restore") {
    if (!arg1) {
      throw new Error("Usage: sqliteBackup.mjs restore <backupSqlitePath> [targetSqlitePath]");
    }
    const dst = arg2 || defaultStudioSqlitePath();
    const result = restoreSqliteDatabase(arg1, dst);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  throw new Error(
    "Usage: sqliteBackup.mjs <backup|verify|restore> [sourceOrBackupPath] [destPath]",
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    runCli();
  } catch (err) {
    process.stderr.write(`[sqliteBackup] ERROR: ${err?.message || String(err)}\n`);
    process.exit(1);
  }
}
