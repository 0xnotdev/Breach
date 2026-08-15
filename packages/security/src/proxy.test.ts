import { describe, expect, it } from "vitest";
import { connect, createServer, type Server } from "node:net";
import { allowedTunnelTarget, createEgressProxy } from "./proxy.js";

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (typeof address !== "object" || address === null) throw new Error("Test server did not bind");
  return address.port;
}

async function connectResponse(port: number, authority: string): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const socket = connect({ port, host: "127.0.0.1" });
    const chunks: Buffer[] = [];
    const timeout = setTimeout(() => { socket.destroy(); reject(new Error("Proxy response timed out")); }, 2_000);
    socket.once("connect", () => socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`));
    socket.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
      const response = Buffer.concat(chunks).toString("utf8");
      if (response.includes("\r\n\r\n")) {
        clearTimeout(timeout);
        socket.destroy();
        resolve(response);
      }
    });
    socket.once("error", (error) => { clearTimeout(timeout); reject(error); });
  });
}

describe("egress proxy policy", () => {
  it("egressProxyAllowsOnlyNamedTlsDestinations", () => {
    expect(allowedTunnelTarget("api.github.com:443")).toEqual({ host: "api.github.com", port: 443 });
    expect(allowedTunnelTarget("API.OSV.DEV:443")).toEqual({ host: "api.osv.dev", port: 443 });
    for (const authority of [
      "api.github.com:80",
      "api.github.com:444",
      "github.com:443",
      "example.test:443",
      "api.github.com.example.test:443",
      "api.github.com.:443",
      "user@api.github.com:443",
      "127.0.0.1:443",
      "[::1]:443",
      "api.github.com:443/path",
    ]) expect(allowedTunnelTarget(authority)).toBeNull();
  });

  it("establishes only an approved CONNECT tunnel", async () => {
    const upstream = createServer(() => undefined);
    const upstreamPort = await listen(upstream);
    const attempts: Array<{ port: number; host: string }> = [];
    const proxy = createEgressProxy((port, host) => {
      attempts.push({ port, host });
      return connect({ port: upstreamPort, host: "127.0.0.1" });
    });
    const proxyPort = await listen(proxy);
    try {
      await expect(connectResponse(proxyPort, "api.github.com:443")).resolves.toMatch(/^HTTP\/1\.1 200 Connection Established/u);
      await expect(connectResponse(proxyPort, "example.test:443")).resolves.toMatch(/^HTTP\/1\.1 403 Forbidden/u);
      expect(attempts).toEqual([{ port: 443, host: "api.github.com" }]);
    } finally {
      proxy.closeAllConnections();
      await Promise.all([
        new Promise<void>((resolve, reject) => proxy.close((error) => { if (error === undefined) resolve(); else reject(error); })),
        new Promise<void>((resolve, reject) => upstream.close((error) => { if (error === undefined) resolve(); else reject(error); })),
      ]);
    }
  });
});
