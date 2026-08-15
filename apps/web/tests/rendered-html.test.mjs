import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { access, readFile, readdir } from "node:fs/promises";
import { createServer } from "node:http";
import test, { after, before } from "node:test";

const templateRoot = new URL("../", import.meta.url);

const port = 4300 + process.pid % 500;
const baseUrl = `http://127.0.0.1:${String(port)}`;
let server;
let upstream;
let upstreamAuthorization = "";
const operatorToken = "operator-runtime-secret-987654321";
const liveFinding = {
  findingId: "76a23814-bfc1-4c15-9444-f7019803e6dd",
  detectedAt: "2026-08-15T12:00:00.000Z",
  repository: { id: 41, fullName: "fixture/live-service", url: "https://github.com/fixture/live-service" },
  revision: { ref: "refs/heads/main", sha: "a827f9c" },
  category: "command_injection",
  cwe: "CWE-78",
  severity: "critical",
  confidence: 0.96,
  exploitability: { score: 96, level: "high_confidence_static_path", attackerSourceIdentified: true, completeDataflowObserved: true, sanitizerObserved: false, authBarrierObserved: false, runtimeVerified: false, activeTestingPerformed: false, deploymentConfirmed: false },
  path: [{ file: "src/routes/render.ts", line: 42, role: "source", symbol: "req.body.filename", edge: "argument" }, { file: "src/routes/render.ts", line: 45, role: "sink", symbol: "child_process.exec", edge: "call" }],
  reviewState: "UNREVIEWED",
};

before(async () => {
  upstream = createServer((request, response) => {
    upstreamAuthorization = request.headers.authorization ?? "";
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ findings: [liveFinding] }));
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const address = upstream.address();
  if (typeof address !== "object" || address === null) throw new Error("Mock operator API did not bind");
  server = spawn(process.execPath, ["node_modules/vinext/dist/cli.js", "start", "--port", String(port), "--hostname", "127.0.0.1"], {
    cwd: templateRoot,
    env: { ...process.env, API_INTERNAL_URL: `http://127.0.0.1:${String(address.port)}`, OPERATOR_TOKEN: operatorToken },
    stdio: "ignore",
  });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    let response;
    try { response = await fetch(baseUrl); } catch { response = undefined; }
    if (response?.ok === true) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Production server did not become ready");
});

after(() => { server?.kill(); upstream?.close(); });

function render(path = "/") {
  return fetch(`${baseUrl}${path}`, { headers: { accept: "text/html" } });
}

test("server-renders the findings-first operator console", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Breach · Passive exploitability console<\/title>/i);
  assert.match(html, /SECURITY STREAM/);
  assert.match(html, />Findings</);
  assert.match(html, />Stream</);
  assert.match(html, />System</);
  assert.match(html, /Loading findings from the operator API/);
  assert.match(html, /STATIC EVIDENCE ONLY/);
  assert.doesNotMatch(html, /Repository secure/i);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|Your site is taking shape/);

  const source = await readFile(new URL("app/ui/FindingsConsole.tsx", templateRoot), "utf8");
  assert.match(source, /No surfaced finding matches these filters/);
});

test("frontendNeverImportsDemoFindingsInProduction", async () => {
  const source = await readFile(new URL("app/ui/FindingsConsole.tsx", templateRoot), "utf8");
  assert.doesNotMatch(source, /demoFindings|from\s+["'][^"']*data["']/u);
  assert.match(source, /\/api\/findings/u);
});

test("frontendDoesNotContainOperatorToken", async () => {
  const clientRoot = new URL("dist/client/", templateRoot);
  const pending = [clientRoot];
  const files = [];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const target = new URL(entry.name + (entry.isDirectory() ? "/" : ""), directory);
      if (entry.isDirectory()) pending.push(target);
      else files.push(target);
    }
  }
  const textAssets = files.filter((file) => /\.(?:html|js|css|json)$/u.test(file.pathname));
  const contents = (await Promise.all(textAssets.map((file) => readFile(file, "utf8")))).join("\n");
  assert.doesNotMatch(contents, new RegExp(`OPERATOR_TOKEN|NEXT_PUBLIC_OPERATOR_TOKEN|operator-test-token|${operatorToken}`, "u"));
  const serverSource = await readFile(new URL("app/server/operator-api.ts", templateRoot), "utf8");
  assert.match(serverSource, /process\.env\.OPERATOR_TOKEN/u);
  assert.doesNotMatch(serverSource, /NEXT_PUBLIC_/u);
});

test("same-origin findings route injects authorization server-side", async () => {
  const response = await fetch(`${baseUrl}/api/findings?severity=critical&limit=100`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(upstreamAuthorization, `Bearer ${operatorToken}`);
  const payload = await response.json();
  assert.deepEqual(payload, { findings: [liveFinding] });

  const rejected = await fetch(`${baseUrl}/api/findings?target=https://example.com`);
  assert.equal(rejected.status, 400);
});

test("removes every disposable starter artifact", async () => {
  await assert.rejects(access(new URL("app/_sites-preview/SkeletonPreview.tsx", templateRoot)));
  await assert.rejects(access(new URL("app/_sites-preview/preview.css", templateRoot)));
  await assert.rejects(access(new URL("public/file.svg", templateRoot)));
  await assert.rejects(access(new URL("public/globe.svg", templateRoot)));
  await assert.rejects(access(new URL("public/window.svg", templateRoot)));
});

test("renders semantic investigation evidence and review controls", async () => {
  const response = await render("/findings/cmd-injection-a827f9c");
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /Investigation/);
  assert.match(html, /ENTRY.*SOURCE.*FLOW.*SINK/s);
  assert.match(html, /req\.body\.filename/);
  assert.match(html, /child_process\.exec/);
  assert.match(html, /Reasons surfaced/);
  assert.match(html, /Observed barriers/);
  assert.match(html, /Coverage &amp; limitations/);
  assert.match(html, /Static evidence, not runtime confirmation/);
  assert.match(html, /CONFIRMED/);
  assert.match(html, /FALSE POSITIVE/);
  assert.match(html, /UNCERTAIN/);
  assert.match(html, /Open on GitHub/);
  assert.match(html, /blob\/a827f9c\/src\/routes\/render\.ts#L42/);
});

test("renders secret details without retaining the raw value", async () => {
  const response = await render("/findings/secret-52f7ab19");
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /AWS Secret Access Key/);
  assert.match(html, /\.env:8/);
  assert.match(html, /Fingerprint/);
  assert.match(html, /9ad3…17e2/);
  assert.match(html, /Raw value NOT RETAINED/);
  assert.doesNotMatch(html, /AKIA[0-9A-Z]{16}/);
});

test("renders every sanitized public scan state in the live stream", async () => {
  const response = await render("/stream");
  assert.equal(response.status, 200);
  const html = await response.text();
  for (const state of ["DISCOVERED", "SKIPPED", "WAITING_FOR_COMMIT", "READY", "SCANNING", "SCANNED_NO_FINDINGS", "SCANNED_FINDINGS", "PARTIAL", "FAILED", "RATE_LIMITED"]) assert.match(html, new RegExp(state));
  assert.match(html, /Live state transitions/);
  assert.match(html, /Metadata only/i);
  assert.doesNotMatch(html, /raw_(?:body|content|secret)|source_code/i);
});

test("renders complete system validation and safety metrics", async () => {
  const response = await render("/system");
  assert.equal(response.status, 200);
  const html = await response.text();
  for (const metric of ["Throughput", "Selection funnel", "GitHub quota", "Request cost", "Scan latency", "Reviewed precision", "Partial / failed", "Canary retention"]) assert.match(html, new RegExp(metric));
  assert.match(html, /DEGRADED/);
  assert.match(html, /SAFE/);
  assert.match(html, /0 retention violations/);
});
