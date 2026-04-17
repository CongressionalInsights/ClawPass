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

async function main(): Promise<void> {
  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const repoRoot = resolve(scriptDir, "..");
  const tmpRoot = await mkdtemp(join(tmpdir(), "clawpass-ts-"));
  const port = await reservePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const pythonPath = join(repoRoot, ".venv", "bin", "python");
  const pythonPathEnv = process.env.PYTHONPATH ? `${join(repoRoot, "src")}:${process.env.PYTHONPATH}` : join(repoRoot, "src");
  let stdout = "";
  let stderr = "";

  const server = spawn(pythonPath, ["-m", "clawpass_server.main"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      PYTHONPATH: pythonPathEnv,
      CLAWPASS_DB_PATH: join(tmpRoot, "clawpass-ts.db"),
      CLAWPASS_HOST: "127.0.0.1",
      CLAWPASS_PORT: String(port),
      CLAWPASS_EXPECTED_ORIGIN: baseUrl,
      CLAWPASS_EXPECTED_ORIGINS: baseUrl,
      CLAWPASS_WEBHOOK_TIMEOUT_SECONDS: "0.1",
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

    const client = new ClawPassClient({ baseUrl });
    const created = await client.createApprovalRequest({
      request_id: "ts-sdk-roundtrip",
      action_type: "sdk.roundtrip",
      action_hash: "sha256:ts-sdk-roundtrip",
      risk_level: "low",
      requester_id: "ts-sdk-benchmark",
    });
    if (created.id !== "ts-sdk-roundtrip" || created.status !== "PENDING") {
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

    const events = await client.listWebhookEvents({
      requestId: created.id,
      status: "skipped",
      eventType: "approval.cancelled",
      limit: 10,
    });
    if (!events.length || events[0].event_type !== "approval.cancelled") {
      throw new Error(`unexpected webhook events: ${JSON.stringify(events)}`);
    }

    const summary = await client.getWebhookSummary();
    if (
      summary.backlog_count !== 0 ||
      summary.stalled_backlog_count !== 0 ||
      summary.redelivery_count !== 0 ||
      summary.health_state !== "healthy" ||
      summary.alerts.length !== 0
    ) {
      throw new Error(`unexpected webhook summary: ${JSON.stringify(summary)}`);
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
