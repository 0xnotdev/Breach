import { createServer, type Server } from "node:http";
import { connect as connectTcp, type Socket } from "node:net";
import { pathToFileURL } from "node:url";

const allowedHosts = new Set(["api.github.com", "api.osv.dev"]);

export interface TunnelTarget {
  readonly host: string;
  readonly port: 443;
}

export function allowedTunnelTarget(authority: string): TunnelTarget | null {
  const match = /^([A-Za-z0-9.-]+):(\d{1,5})$/u.exec(authority);
  if (match === null) return null;
  const hostText = match[1];
  const portText = match[2];
  if (hostText === undefined || portText === undefined) return null;
  const host = hostText.toLocaleLowerCase("en-US");
  const port = Number(portText);
  if (port !== 443 || host.endsWith(".") || !allowedHosts.has(host)) return null;
  return { host, port: 443 };
}

export function createEgressProxy(
  connectUpstream: (port: number, host: string) => Socket = (port, host) => connectTcp({ port, host }),
): Server {
  const server = createServer({ maxHeaderSize: 8_192 }, (request, response) => {
    if (request.method === "GET" && request.url === "/healthz") {
      response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      response.end('{"status":"live"}');
      return;
    }
    response.writeHead(403, { "content-type": "application/json", connection: "close" });
    response.end('{"error":"proxy_request_denied"}');
  });
  server.requestTimeout = 5_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 5_000;
  server.on("connect", (request, client, head) => {
    const target = allowedTunnelTarget(request.url ?? "");
    if (target === null) {
      client.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      return;
    }
    const upstream = connectUpstream(target.port, target.host);
    const close = () => {
      if (!client.destroyed) client.destroy();
      if (!upstream.destroyed) upstream.destroy();
    };
    upstream.setTimeout(30_000, close);
    client.once("error", close);
    client.once("close", () => { if (!upstream.destroyed) upstream.destroy(); });
    upstream.once("error", () => {
      if (!client.destroyed) client.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
      close();
    });
    upstream.once("close", () => { if (!client.destroyed) client.destroy(); });
    upstream.once("connect", () => {
      client.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: breach-egress\r\n\r\n");
      if (head.byteLength > 0) upstream.write(head);
      client.pipe(upstream);
      upstream.pipe(client);
    });
  });
  return server;
}

export async function startEgressProxy(port = Number(process.env.EGRESS_PROXY_PORT ?? "3128")): Promise<Server> {
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error("EGRESS_PROXY_PORT is invalid");
  const server = createEgressProxy();
  await new Promise<void>((resolve) => server.listen(port, "0.0.0.0", resolve));
  return server;
}

const invokedPath = process.argv[1];
/* v8 ignore start -- trivial process entry wrapper; startEgressProxy is exercised directly. */
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  startEgressProxy().catch(() => {
    process.stderr.write("Breach egress proxy failed to start\n");
    process.exitCode = 1;
  });
}
/* v8 ignore stop */
