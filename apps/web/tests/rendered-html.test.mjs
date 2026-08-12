import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const templateRoot = new URL("../", import.meta.url);

async function render(path = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`http://localhost${path}`, { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
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
