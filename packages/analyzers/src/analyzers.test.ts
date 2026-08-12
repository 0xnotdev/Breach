import { describe, expect, it } from "vitest";
import {
  SecretScanner,
  correlateOsv,
  parseDependencies,
  scanConfiguration,
  type OsvBatchRequest,
  type OsvBatchResponse,
  type OsvTransport,
} from "./index.js";

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);

describe("passive secret and dependency analysis", () => {
  it("emits only deterministic fingerprints for structured and contextual fake secrets", () => {
    const fakeAwsSecret = "9vK2Lm4Np6Qr8St0Uv2Wx4Yz6Ab8Cd0Ef2Gh4Ij6";
    const fakeGitHubToken = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    const fakeGenericSecret = "q7W9e2R4t6Y8u0I2o4P6a8S0d2F4g6H8";
    const scanner = new SecretScanner("test-key-32-bytes-minimum-1234567890");

    const findings = scanner.scan([
      {
        path: ".env",
        bytes: bytes(
          `AWS_SECRET_ACCESS_KEY=${fakeAwsSecret}\n` +
            `GITHUB_TOKEN=${fakeGitHubToken}\n` +
            "API_KEY=your_api_key_here\n" +
            `CUSTOM_PASSWORD=${fakeGenericSecret}\n`,
        ),
      },
      {
        path: "fixture.pem",
        bytes: bytes(
          "-----BEGIN PRIVATE KEY-----\nFAKE_CANARY_MATERIAL_NOT_A_KEY\n-----END PRIVATE KEY-----\n",
        ),
      },
      {
        path: "package-lock.json",
        bytes: bytes('"integrity": "sha512-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk"'),
      },
    ]);

    expect(findings.map((finding) => finding.type)).toEqual([
      "AWS Secret Access Key",
      "GitHub token",
      "Generic high-entropy credential",
      "Private key",
    ]);
    expect(findings[0]).toMatchObject({
      path: ".env",
      line: 1,
      provider: "AWS",
      fingerprint: "c58bd9bfee5e5cd3036b264e0fc716834e069fd6e858e44a2db51e8a3ebff0e6",
    });
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain(fakeAwsSecret);
    expect(serialized).not.toContain(fakeGitHubToken);
    expect(serialized).not.toContain(fakeGenericSecret);
    expect(serialized).not.toContain("FAKE_CANARY_MATERIAL_NOT_A_KEY");
    expect(serialized).not.toContain("your_api_key_here");
  });

  it("parses exact installed versions from prioritized package formats", () => {
    const fixtures: Array<[string, string, string, string, string]> = [
      [
        "package-lock.json",
        '{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}',
        "npm",
        "lodash",
        "4.17.20",
      ],
      ["requirements.txt", "flask==2.0.1\nrequests>=2", "PyPI", "flask", "2.0.1"],
      ["go.mod", "require github.com/acme/module v1.2.3", "Go", "github.com/acme/module", "v1.2.3"],
      ["go.sum", "github.com/acme/check v1.4.0 h1:FAKEHASH", "Go", "github.com/acme/check", "v1.4.0"],
      [
        "Cargo.lock",
        '[[package]]\nname = "serde"\nversion = "1.0.130"\n',
        "crates.io",
        "serde",
        "1.0.130",
      ],
      [
        "Cargo.toml",
        '[dependencies]\nserde = "1.0.130"\n',
        "crates.io",
        "serde",
        "1.0.130",
      ],
      [
        "pyproject.toml",
        'dependencies = ["httpx==0.24.1"]\n',
        "PyPI",
        "httpx",
        "0.24.1",
      ],
      ["Gemfile.lock", "GEM\n  specs:\n    rack (2.2.3)\n", "RubyGems", "rack", "2.2.3"],
      [
        "pom.xml",
        "<dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.2.0</version></dependency>",
        "Maven",
        "org.example:demo",
        "1.2.0",
      ],
      ["pnpm-lock.yaml", "packages:\n  lodash@4.17.20:\n    resolution: {}", "npm", "lodash", "4.17.20"],
      ["yarn.lock", 'lodash@^4.17.0:\n  version "4.17.20"', "npm", "lodash", "4.17.20"],
      [
        "composer.lock",
        '{"packages":[{"name":"vendor/library","version":"1.4.2"}]}',
        "Packagist",
        "vendor/library",
        "1.4.2",
      ],
      [
        "packages.lock.json",
        '{"dependencies":{"net8.0":{"Newtonsoft.Json":{"resolved":"13.0.1"}}}}',
        "NuGet",
        "Newtonsoft.Json",
        "13.0.1",
      ],
    ];

    for (const [path, content, ecosystem, name, version] of fixtures) {
      expect(parseDependencies(path, bytes(content))).toContainEqual({ ecosystem, name, version, path });
    }
  });

  it("ignores unresolved ranges and malformed manifests", () => {
    expect(parseDependencies("package.json", bytes('{"dependencies":{"react":"^19.0.0"}}'))).toEqual([]);
    expect(parseDependencies("requirements.txt", bytes("flask>=2\nrequests~=2.3"))).toEqual([]);
    expect(parseDependencies("package-lock.json", bytes("{not json"))).toEqual([]);
  });

  it("queries OSV in batches of at most 100 and returns advisory metadata only", async () => {
    const calls: OsvBatchRequest[] = [];
    const transport: OsvTransport = {
      queryBatch(request) {
        calls.push(request);
        const results = request.queries.map((_query, index) =>
          calls.length === 3 && index === 4
            ? { vulns: [{ id: "OSV-FAKE-1", summary: "Controlled advisory fixture" }] }
            : {},
        );
        return Promise.resolve({ results } satisfies OsvBatchResponse);
      },
    };
    const packages = Array.from({ length: 205 }, (_, index) => ({
      ecosystem: "npm",
      name: `fixture-${String(index)}`,
      version: "1.0.0",
      path: "package-lock.json",
    }));

    const findings = await correlateOsv(packages, transport);

    expect(calls.map((call) => call.queries.length)).toEqual([100, 100, 5]);
    expect(findings).toEqual([
      {
        category: "vulnerable_dependency",
        ecosystem: "npm",
        package: "fixture-204",
        version: "1.0.0",
        advisoryId: "OSV-FAKE-1",
        summary: "Controlled advisory fixture",
        path: "package-lock.json",
      },
    ]);
    expect(JSON.stringify(calls)).not.toContain("source");
  });

  it("surfaces high-risk CI, Docker, IaC, and configuration semantics without snippets", () => {
    const findings = scanConfiguration([
      {
        path: ".github/workflows/release.yml",
        bytes: bytes(
          "on: pull_request_target\n" +
            "permissions: write-all\n" +
            "steps:\n" +
            "  - uses: actions/checkout@main\n" +
            "  - run: echo ${{ secrets.DEPLOY_KEY }}\n",
        ),
      },
      {
        path: "Dockerfile",
        bytes: bytes(
          "FROM node:24\n" +
            "ARG API_TOKEN\n" +
            "RUN curl https://example.invalid/install.sh | sh\n" +
            "RUN chmod 777 /app\n",
        ),
      },
      {
        path: "infra/main.tf",
        bytes: bytes(
          'from_port = 22\nto_port = 22\ncidr_blocks = ["0.0.0.0/0"]\nacl = "public-read"\n',
        ),
      },
      {
        path: "k8s/deployment.yaml",
        bytes: bytes("securityContext:\n  privileged: true\n  allowPrivilegeEscalation: true\n"),
      },
      {
        path: "src/config.ts",
        bytes: bytes(
          "const tls = { rejectUnauthorized: false };\n" +
            "const cors = { origin: '*', credentials: true };\n",
        ),
      },
    ]);

    expect(findings.map((finding) => finding.ruleId)).toEqual([
      "github_actions.pull_request_target",
      "github_actions.write_all_permissions",
      "github_actions.unpinned_action",
      "github_actions.secret_in_shell",
      "docker.secret_in_arg_env",
      "docker.download_pipe_shell",
      "docker.world_writable",
      "docker.root_user",
      "terraform.public_sensitive_ingress",
      "terraform.public_storage",
      "kubernetes.privileged_container",
      "kubernetes.privilege_escalation",
      "tls.verification_disabled",
      "cors.wildcard_credentials",
    ]);
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain("DEPLOY_KEY");
    expect(serialized).not.toContain("example.invalid");
    expect(findings.every((finding) => !("snippet" in finding))).toBe(true);
  });
});
