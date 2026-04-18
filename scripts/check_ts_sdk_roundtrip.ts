import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";

import { ClawPassClient } from "../ts-sdk/src/index.ts";

async function reservePort(): Promise<number> {
  return await new Promise((resolvePort, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("failed to reserve port"));
        return;
      }
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolvePort(address.port);
      });
    });
  });
}

async function waitForHealthy(baseUrl: string, server: ReturnType<typeof spawn>): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (server.exitCode !== null) {
      throw new Error(`server exited early with code ${server.exitCode}`);
    }
    try {
      const response = await fetch(`${baseUrl}/healthz`);
      if (response.ok) {
        return;
      }
    } catch {}
    await delay(100);
  }
  throw new Error("server did not become healthy in time");
}

async function stopServer(server: ReturnType<typeof spawn>): Promise<void> {
  if (server.exitCode !== null) {
    return;
  }
  server.kill("SIGTERM");
  await Promise.race([
    new Promise<void>((resolveStop) => server.once("exit", () => resolveStop())),
    delay(3000),
  ]);
  if (server.exitCode === null) {
    server.kill("SIGKILL");
    await new Promise<void>((resolveStop) => server.once("exit", () => resolveStop()));
  }
}

async function runPython(
  repoRoot: string,
  env: Record<string, string>,
  code: string,
): Promise<string> {
  const pythonPath = join(repoRoot, ".venv", "bin", "python");
  const pythonPathEnv = process.env.PYTHONPATH
    ? `${join(repoRoot, "src")}:${process.env.PYTHONPATH}`
    : join(repoRoot, "src");
  return await new Promise((resolveOutput, reject) => {
    let stdout = "";
    let stderr = "";
    const processHandle = spawn(pythonPath, ["-c", code], {
      cwd: repoRoot,
      env: {
        ...process.env,
        ...env,
        PYTHONPATH: pythonPathEnv,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    processHandle.stdout?.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    processHandle.stderr?.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    processHandle.once("exit", (code) => {
      if (code === 0) {
        resolveOutput(stdout.trim());
        return;
      }
      reject(new Error(stderr.trim() || stdout.trim() || `python exited with code ${code}`));
    });
  });
}

async function issueProducerApiKey(repoRoot: string, dbPath: string, baseUrl: string): Promise<string> {
  const script = `
from pathlib import Path
import os

from clawpass_server.adapters.ethereum_adapter import EthereumAdapter
from clawpass_server.adapters.webauthn_adapter import WebAuthnAdapter
from clawpass_server.core.config import Settings
from clawpass_server.core.database import Database
from clawpass_server.core.service import ClawPassService

settings = Settings(
    db_path=Path(os.environ["CLAWPASS_DB_PATH"]),
    host="127.0.0.1",
    port=8081,
    base_url=os.environ["CLAWPASS_BASE_URL"],
    rp_id="localhost",
    rp_name="ClawPass",
    expected_origin=os.environ["CLAWPASS_BASE_URL"],
    expected_origins=[os.environ["CLAWPASS_BASE_URL"]],
    webauthn_timeout_ms=60000,
    challenge_ttl_minutes=10,
    approval_default_ttl_minutes=30,
    admin_session_ttl_minutes=720,
    instance_id="ts-sdk-roundtrip",
    session_secret="ts-sdk-roundtrip-session",
    session_secret_configured=True,
    bootstrap_token="ts-sdk-roundtrip-bootstrap",
    deployment_mode="development",
    webhook_timeout_seconds=0.1,
    webhook_delivery_lease_seconds=30,
    webhook_retry_poll_seconds=0,
    webhook_auto_retry_limit=2,
    webhook_auto_retry_base_delay_seconds=30,
    webhook_auto_retry_max_delay_seconds=300,
    webhook_auto_retry_jitter_seconds=10,
    webhook_backlog_alert_threshold=1,
    webhook_backlog_alert_after_seconds=30,
    webhook_failure_rate_alert_threshold=0.25,
    webhook_event_retention_days=14,
    webhook_retry_history_retention_days=30,
    webhook_endpoint_auto_mute_threshold=3,
    webhook_endpoint_auto_mute_seconds=600,
    webhook_secret=None,
)
db = Database(settings.db_path)
db.ensure_ready()
service = ClawPassService(
    settings=settings,
    db=db,
    webauthn=WebAuthnAdapter(settings),
    ethereum=EthereumAdapter(),
)
producer = service.create_producer(
    payload=type("ProducerPayload", (), {"name": "ts-sdk-roundtrip", "description": "ts sdk roundtrip"})()
)
key = service.issue_producer_key(
    producer.id,
    payload=type("ProducerKeyPayload", (), {"label": "primary"})(),
)
print(key.api_key)
`;
  return await runPython(
    repoRoot,
    {
      CLAWPASS_DB_PATH: dbPath,
      CLAWPASS_BASE_URL: baseUrl,
    },
    script,
  );
}

async function main(): Promise<void> {
  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const repoRoot = resolve(scriptDir, "..");
  const tmpRoot = await mkdtemp(join(tmpdir(), "clawpass-ts-"));
  const dbPath = join(tmpRoot, "clawpass-ts.db");
  const port = await reservePort();
  const baseUrl = `http://localhost:${port}`;
  const pythonPath = join(repoRoot, ".venv", "bin", "python");
  const pythonPathEnv = process.env.PYTHONPATH ? `${join(repoRoot, "src")}:${process.env.PYTHONPATH}` : join(repoRoot, "src");
  const apiKey = await issueProducerApiKey(repoRoot, dbPath, baseUrl);
  let stdout = "";
  let stderr = "";

  const server = spawn(pythonPath, ["-m", "clawpass_server.main"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      PYTHONPATH: pythonPathEnv,
      CLAWPASS_DB_PATH: dbPath,
      CLAWPASS_HOST: "127.0.0.1",
      CLAWPASS_PORT: String(port),
      CLAWPASS_BASE_URL: baseUrl,
      CLAWPASS_EXPECTED_ORIGIN: baseUrl,
      CLAWPASS_EXPECTED_ORIGINS: baseUrl,
      CLAWPASS_SESSION_SECRET: "ts-sdk-roundtrip-session",
      CLAWPASS_BOOTSTRAP_TOKEN: "ts-sdk-roundtrip-bootstrap",
      CLAWPASS_WEBHOOK_TIMEOUT_SECONDS: "0.1",
      CLAWPASS_WEBHOOK_RETRY_POLL_SECONDS: "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  server.stdout?.on("data", (chunk) => {
    stdout += chunk.toString();
  });
  server.stderr?.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  try {
    await waitForHealthy(baseUrl, server);

    const client = new ClawPassClient({ baseUrl, apiKey });
    const created = await client.createGatedAction({
      request_id: "ts-sdk-roundtrip",
      action_type: "sdk.roundtrip",
      action_hash: "sha256:ts-sdk-roundtrip",
      risk_level: "low",
      requester_id: "ts-sdk-benchmark",
    });
    if (
      created.id !== "ts-sdk-roundtrip" ||
      created.status !== "PENDING" ||
      !created.producer_id ||
      !created.approval_url
    ) {
      throw new Error(`unexpected create response: ${JSON.stringify(created)}`);
    }

    const pending = await client.listApprovalRequests("pending");
    if (!pending.some((request) => request.id === created.id)) {
      throw new Error(`created request missing from pending list: ${JSON.stringify(pending)}`);
    }

    const cancelled = await client.cancelApprovalRequest(created.id, "ts sdk roundtrip cleanup");
    if (cancelled.id !== created.id || cancelled.status !== "CANCELLED") {
      throw new Error(`unexpected cancel response: ${JSON.stringify(cancelled)}`);
    }

    const terminal = await client.waitForFinalDecision(created.id, {
      timeoutMs: 1_000,
      pollIntervalMs: 10,
    });
    if (terminal.id !== created.id || terminal.status !== "CANCELLED") {
      throw new Error(`unexpected terminal response: ${JSON.stringify(terminal)}`);
    }

    const fetched = await client.getApprovalRequest(created.id);
    if (fetched.id !== created.id || fetched.status !== "CANCELLED") {
      throw new Error(`unexpected fetch response: ${JSON.stringify(fetched)}`);
    }

    console.log("ts sdk roundtrip ok");
  } catch (error) {
    const details = [String(error)];
    if (stdout.trim()) {
      details.push(`server stdout:\n${stdout.trim()}`);
    }
    if (stderr.trim()) {
      details.push(`server stderr:\n${stderr.trim()}`);
    }
    throw new Error(details.join("\n\n"));
  } finally {
    await stopServer(server);
    await rm(tmpRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
