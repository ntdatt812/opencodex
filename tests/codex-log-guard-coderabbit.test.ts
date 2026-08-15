import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  getCodexLogGuardProtectionStatus,
  protectCodexLogs,
  unprotectCodexLogs,
} from "../src/codex/log-guard/protection";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function createCurrentLogsDb(path: string): void {
  const db = new Database(path);
  db.exec(`
    CREATE TABLE logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      ts_nanos INTEGER NOT NULL,
      level TEXT NOT NULL,
      target TEXT NOT NULL,
      feedback_log_body TEXT,
      module_path TEXT,
      file TEXT,
      line INTEGER,
      thread_id TEXT,
      process_uuid TEXT,
      estimated_bytes INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX idx_logs_ts ON logs(ts DESC, ts_nanos DESC, id DESC);
    CREATE INDEX idx_logs_thread_id ON logs(thread_id);
    CREATE INDEX idx_logs_thread_id_ts ON logs(thread_id, ts DESC, ts_nanos DESC, id DESC);
    CREATE INDEX idx_logs_process_uuid_threadless_ts
      ON logs(process_uuid, ts DESC, ts_nanos DESC, id DESC)
      WHERE thread_id IS NULL;
  `);
  db.close();
}

function fixture(): { codexHome: string; databasePath: string } {
  const root = mkdtempSync(join(tmpdir(), "ocx-log-guard-cr-protect-"));
  roots.push(root);
  const codexHome = join(root, "codex-home");
  mkdirSync(codexHome);
  writeFileSync(join(codexHome, "config.toml"), "");
  const databasePath = join(codexHome, "logs_2.sqlite");
  createCurrentLogsDb(databasePath);
  return { codexHome, databasePath };
}

function deps(codexHome: string, writeDesiredMode?: (mode: "off" | "compat" | "quiet") => void) {
  let desired: "off" | "compat" | "quiet" = "off";
  return {
    codexHome,
    processCheck: () => ({ state: "ok" as const, processes: [] }),
    readDesiredMode: () => desired,
    writeDesiredMode: (mode: "off" | "compat" | "quiet") => {
      desired = mode;
      writeDesiredMode?.(mode);
    },
    withLock: <T>(_home: string, _db: string, work: () => T) => ({ kind: "completed" as const, value: work() }),
  };
}

describe("CodeRabbit protection regressions", () => {
  test("compatible but unsafe trigger path reports unknown protection state", () => {
    const root = mkdtempSync(join(tmpdir(), "ocx-log-guard-cr-symlink-"));
    roots.push(root);
    const codexHome = join(root, "codex-home");
    mkdirSync(codexHome);
    writeFileSync(join(codexHome, "config.toml"), "");
    const target = join(root, "real-logs.sqlite");
    createCurrentLogsDb(target);
    symlinkSync(target, join(codexHome, "logs_2.sqlite"));

    const status = getCodexLogGuardProtectionStatus(deps(codexHome));
    expect(status.schema.state).toBe("compatible");
    expect(status.protection).toEqual({ desiredMode: "off", observedMode: "collision", state: "unknown" });
  });

  test("successful mutation status honors a fresh unsupported inspection", () => {
    const { codexHome, databasePath } = fixture();
    const result = protectCodexLogs("compat", deps(codexHome, () => {
      const db = new Database(databasePath);
      db.exec("ALTER TABLE logs ADD COLUMN future_field TEXT");
      db.close();
    }));

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status.capabilities.protection.state).toBe("unsupported");
    expect(result.status.protection.state).toBe("unsupported");
  });

  test("unprotect recovers when both exact OpenCodex-owned triggers are present", () => {
    const { codexHome, databasePath } = fixture();
    const testDeps = deps(codexHome);
    expect(protectCodexLogs("compat", testDeps).ok).toBe(true);

    const db = new Database(databasePath);
    db.exec(`
      CREATE TRIGGER opencodex_log_guard_quiet_v1
      BEFORE INSERT ON logs
      WHEN upper(NEW.level) = 'TRACE'
      BEGIN
        SELECT RAISE(IGNORE);
      END;
    `);
    db.close();

    const result = unprotectCodexLogs(testDeps);
    expect(result.ok).toBe(true);
    const inspect = new Database(databasePath, { readonly: true });
    const owned = inspect.query<{ name: string }, []>(
      "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'opencodex_log_guard_%'",
    ).all();
    inspect.close();
    expect(owned).toEqual([]);
  });
});
