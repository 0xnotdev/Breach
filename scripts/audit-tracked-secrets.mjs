import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const tracked = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" })
  .split("\0")
  .filter(Boolean);
const fixturePath = "fixtures/canary-repository/credential.txt";
const fixture = readFileSync(fixturePath, "utf8");
const canary = fixture.slice(fixture.indexOf("=") + 1).trim();
const documentedFakeGitHubToken = ["ghp_", "abcdefghijklmnopqrstuvwxyz1234567890"].join("");
const credentialPatterns = [
  /\bAKIA[0-9A-Z]{16}\b/gu,
  /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/gu,
  new RegExp(
    "-----BEGIN ((?:RSA |EC |OPENSSH )?PRIVATE KEY)-----[\\s\\S]{64,}?-----END \\1-----",
    "gu",
  ),
];
const failures = [];

for (const path of tracked) {
  const bytes = readFileSync(path);
  if (bytes.includes(0)) continue;
  const content = bytes.toString("utf8");
  if (path !== fixturePath && canary.length > 0 && content.includes(canary)) {
    failures.push(`${path}: duplicate controlled canary value`);
  }
  for (const pattern of credentialPatterns) {
    pattern.lastIndex = 0;
    const matches = content.match(pattern) ?? [];
    for (const match of matches) {
      const isDocumentedFake =
        path === "packages/analyzers/src/analyzers.test.ts" && match === documentedFakeGitHubToken;
      if (!isDocumentedFake) failures.push(`${path}: credential-shaped content`);
    }
  }
}

if (failures.length > 0) {
  process.stderr.write(`${failures.join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Audited ${String(tracked.length)} tracked files; no committed credentials or duplicate canary values found.\n`);
}
