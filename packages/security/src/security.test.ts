import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import { SecretScanner } from "@breach/analyzers";
import { CanaryAuditor, EgressPolicy, escapeUntrustedText, parseSafeXml, parseSafeYaml } from "./index.js";

describe("security boundary", () => {
  it("allows only declared service destinations and never follows repository URLs", () => {
    const policy = new EgressPolicy({ internalHosts: ["postgres", "api"] });
    expect(policy.assertAllowed("https://api.github.com/repos/o/r/git/trees/head").hostname).toBe("api.github.com");
    expect(policy.assertAllowed("https://api.osv.dev/v1/querybatch").hostname).toBe("api.osv.dev");
    expect(policy.assertAllowed("http://postgres:5432/health").hostname).toBe("postgres");
    for (const target of ["https://github.com/owner/repository", "https://example.test/payload", "file:///etc/passwd", "https://api.github.com@example.test/"]) expect(() => policy.assertAllowed(target)).toThrow(/egress denied/i);
  });

  it("parses bounded safe YAML while rejecting tags, aliases, controls, and deep input", () => {
    expect(parseSafeYaml("permissions:\n  contents: read\n", { maxBytes: 1000, maxDepth: 4 })).toEqual({ permissions: { contents: "read" } });
    for (const text of ["payload: !!js/function 'x'", "a: &a [*a]", "name: bad\u0000value", "a:\n  b:\n    c:\n      d: 1"]) expect(() => parseSafeYaml(text, { maxBytes: 1000, maxDepth: 3 })).toThrow();
  });

  it("parses bounded XML with DTD, entity expansion, and network identifiers disabled", () => {
    expect(parseSafeXml("<project><name>safe</name></project>", { maxBytes: 1000, maxDepth: 4 })).toEqual({ project: { name: "safe" } });
    for (const text of ["<!DOCTYPE x SYSTEM 'https://example.test/x'><x/>", "<!DOCTYPE x [<!ENTITY y 'boom'>]><x>&y;</x>", "<a><b><c><d>too deep</d></c></b></a>"]) expect(() => parseSafeXml(text, { maxBytes: 1000, maxDepth: 3 })).toThrow();
  });

  it("normalizes Unicode and visibly escapes terminal/control characters", () => {
    expect(escapeUntrustedText("repo\u001b[31m\r\nnaïve\u0301", 30)).toBe("repo\\u{1b}[31m\\r\\nnaïvé");
    expect(escapeUntrustedText("abcdef", 4)).toBe("abc…");
  });

  it("proves a fake canary is absent from every retention surface with one fingerprint", async () => {
    const fixture = new URL("../../../fixtures/canary-repository/credential.txt", import.meta.url);
    const rawFile = await readFile(fixture, "utf8");
    const rawCanary = rawFile.trim().slice(rawFile.indexOf("=") + 1);
    const key = "test-only-fingerprint-key-32-bytes-minimum";
    const [finding] = new SecretScanner(key).scan([{ path: ".env", bytes: new TextEncoder().encode(rawFile) }]);
    expect(finding).toBeDefined();
    if (finding === undefined) throw new Error("Expected canary finding");
    const expected = createHmac("sha256", key).update(rawCanary).digest("hex");
    expect(finding.fingerprint).toBe(expected);

    const proof = new CanaryAuditor(rawCanary, expected).audit({
      database: JSON.stringify(finding), logs: "scan complete", output: "SCANNED_FINDINGS", errors: "", browser: JSON.stringify({ fingerprint: `${expected.slice(0, 8)}…` }), queues: "repo-id:canary", writableLayers: "",
    });
    expect(proof).toEqual({ rawOccurrences: 0, fingerprintOccurrences: 1, surfacesChecked: 7 });
    expect(() => new CanaryAuditor(rawCanary, expected).audit({ database: rawCanary })).toThrow(/raw canary retained/i);
  });

  it("never verifies a discovered credential or derives a network target from it", () => {
    const network = vi.spyOn(globalThis, "fetch");
    const findings = new SecretScanner("test-only-fingerprint-key-32-bytes-minimum").scan([{ path: ".env", bytes: new TextEncoder().encode("API_TOKEN=Zx8v7B6n5M4k3J2h1G0f9D8s7A6p5O4i") }]);
    expect(findings).toHaveLength(1);
    expect(network).not.toHaveBeenCalled();
    network.mockRestore();
  });

  it("declares a non-root read-only worker with bounded writable and process resources", async () => {
    const root = new URL("../../../", import.meta.url);
    const [dockerfile, compose] = await Promise.all([readFile(new URL("deploy/worker.Dockerfile", root), "utf8"), readFile(new URL("compose.yaml", root), "utf8")]);
    expect(dockerfile).toMatch(/USER breach/);
    expect(dockerfile).not.toMatch(/(?:git clone|docker\.sock|COPY\s+fixtures)/i);
    for (const contract of [/read_only:\s*true/, /no-new-privileges:true/, /cap_drop:\s*\n\s*- ALL/, /tmpfs:\s*\n\s*- \/tmp:rw,noexec,nosuid,size=64m/, /pids:\s*128/, /nofile:\s*256/, /core:\s*0/, /memory:\s*512M/, /cpus:\s*['"]?1\.0['"]?/]) expect(compose).toMatch(contract);
    expect(compose).not.toMatch(/docker\.sock|\/[\w./-]*source|swap_limit:\s*-1/i);
  });
});
