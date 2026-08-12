import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import test, { after, before } from "node:test";

const templateRoot = new URL("../", import.meta.url);

const port = 4300 + process.pid % 500;
const baseUrl = `http://127.0.0.1:${String(port)}`;
let server;

before(async () => {
  server = spawn(process.execPath, ["node_modules/vinext/dist/cli.js", "start", "--port", String(port), "--hostname", "127.0.0.1"], { cwd: templateRoot, stdio: "ignore" });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { const response = await fetch(baseUrl); if (response.ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Production server did not become ready");
});

after(() => { server?.kill(); });

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
  assert.match(html, /Command Injection/);
  assert.match(html, /96<span[^>]*>\/100<\/span>/);
  assert.match(html, /STATIC EVIDENCE ONLY/);
  assert.doesNotMatch(html, /Repository secure/i);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|Your site is taking shape/);

  const source = await readFile(new URL("app/ui/FindingsConsole.tsx", templateRoot), "utf8");
  assert.match(source, /No surfaced finding within modeled coverage/);
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
