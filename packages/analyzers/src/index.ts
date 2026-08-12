import { createHmac } from "node:crypto";

export interface AnalyzerFile {
  readonly path: string;
  readonly bytes: Uint8Array;
}

export interface SecretFindingDraft {
  readonly category: "secret_exposure";
  readonly ruleId: string;
  readonly type: string;
  readonly provider?: string;
  readonly severity: "critical" | "high";
  readonly confidence: number;
  readonly path: string;
  readonly line: number;
  readonly fingerprint: string;
}

interface SecretMatch {
  index: number;
  value: string;
  ruleId: string;
  type: string;
  provider?: string;
  severity: "critical" | "high";
  confidence: number;
}

const placeholderFragments = [
  "your_api_key",
  "your-api-key",
  "replace_me",
  "replace-me",
  "changeme",
  "example",
  "dummy",
  "placeholder",
  "xxxxxxxx",
  "<token>",
  "${",
];

function isPlaceholder(value: string): boolean {
  const lower = value.toLocaleLowerCase("en-US");
  return placeholderFragments.some((fragment) => lower.includes(fragment));
}

function lineAt(text: string, index: number): number {
  let line = 1;
  for (let offset = 0; offset < index; offset += 1) {
    if (text.charCodeAt(offset) === 10) line += 1;
  }
  return line;
}

function entropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index] ?? "";
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  let result = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    result -= probability * Math.log2(probability);
  }
  return result;
}

function isIntegrityOrGeneratedPath(path: string): boolean {
  const lower = path.toLocaleLowerCase("en-US");
  return (
    /(?:^|\/)(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|cargo\.lock|go\.sum)$/u.test(lower) ||
    /(?:^|\/)(?:dist|build|vendor|node_modules)(?:\/|$)/u.test(lower)
  );
}

function collectKnownMatches(text: string): SecretMatch[] {
  const matches: SecretMatch[] = [];
  const aws = /(?:^|\n)[ \t]*(?:export[ \t]+)?AWS_SECRET_ACCESS_KEY[ \t]*=[ \t]*["']?([A-Za-z0-9/+=]{40,128})["']?/gu;
  for (const match of text.matchAll(aws)) {
    const value = match[1];
    if (value === undefined || isPlaceholder(value)) continue;
    const relative = match[0].indexOf(value);
    matches.push({
      index: match.index + Math.max(relative, 0),
      value,
      ruleId: "secret.aws_secret_access_key",
      type: "AWS Secret Access Key",
      provider: "AWS",
      severity: "critical",
      confidence: 0.98,
    });
  }

  const github = /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/gu;
  for (const match of text.matchAll(github)) {
    const value = match[0];
    if (isPlaceholder(value)) continue;
    matches.push({
      index: match.index,
      value,
      ruleId: "secret.github_token",
      type: "GitHub token",
      provider: "GitHub",
      severity: "critical",
      confidence: 0.99,
    });
  }

  const privateKey = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{1,65536}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gu;
  for (const match of text.matchAll(privateKey)) {
    matches.push({
      index: match.index,
      value: match[0],
      ruleId: "secret.private_key",
      type: "Private key",
      severity: "critical",
      confidence: 0.99,
    });
  }

  const databaseUrl = /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@/]+:[^\s@/]{8,}@[^\s"']+)/giu;
  for (const match of text.matchAll(databaseUrl)) {
    const value = match[1];
    if (value === undefined || isPlaceholder(value)) continue;
    matches.push({
      index: match.index,
      value,
      ruleId: "secret.database_url",
      type: "Credentialed database URL",
      severity: "critical",
      confidence: 0.96,
    });
  }
  return matches;
}

function collectGenericMatches(text: string, occupiedLines: ReadonlySet<number>): SecretMatch[] {
  const matches: SecretMatch[] = [];
  const assignment = /(?:^|\n)[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY)[A-Za-z0-9_]*)[ \t]*[:=][ \t]*["']?([^\s"'#,;]{16,512})["']?/giu;
  for (const match of text.matchAll(assignment)) {
    const value = match[2];
    if (value === undefined || isPlaceholder(value) || entropy(value) < 3.5) continue;
    const index = match.index + Math.max(match[0].indexOf(value), 0);
    if (occupiedLines.has(lineAt(text, index))) continue;
    matches.push({
      index,
      value,
      ruleId: "secret.generic_contextual",
      type: "Generic high-entropy credential",
      severity: "high",
      confidence: 0.82,
    });
  }
  return matches;
}

export class SecretScanner {
  readonly #fingerprintKey: string | Uint8Array;

  constructor(fingerprintKey: string | Uint8Array) {
    const keyLength = typeof fingerprintKey === "string"
      ? new TextEncoder().encode(fingerprintKey).byteLength
      : fingerprintKey.byteLength;
    if (keyLength < 32) throw new Error("Fingerprint key must be at least 32 bytes");
    this.#fingerprintKey = fingerprintKey;
  }

  scan(files: readonly AnalyzerFile[]): SecretFindingDraft[] {
    const findings: SecretFindingDraft[] = [];
    for (const file of files) {
      const text = new TextDecoder("utf-8", { fatal: false }).decode(file.bytes);
      const known = collectKnownMatches(text);
      const occupiedLines = new Set(known.map((match) => lineAt(text, match.index)));
      const matches = isIntegrityOrGeneratedPath(file.path)
        ? known
        : [...known, ...collectGenericMatches(text, occupiedLines)];
      matches.sort((left, right) => left.index - right.index || left.ruleId.localeCompare(right.ruleId));

      for (const match of matches) {
        const fingerprint = createHmac("sha256", this.#fingerprintKey)
          .update(match.value, "utf8")
          .digest("hex");
        findings.push({
          category: "secret_exposure",
          ruleId: match.ruleId,
          type: match.type,
          ...(match.provider === undefined ? {} : { provider: match.provider }),
          severity: match.severity,
          confidence: match.confidence,
          path: file.path,
          line: lineAt(text, match.index),
          fingerprint,
        });
      }
    }
    return findings;
  }
}

export interface Dependency {
  ecosystem: string;
  name: string;
  version: string;
  path: string;
}

function isExactVersion(version: string): boolean {
  return /^(?:v?\d|[a-f0-9]{7,40}$)[0-9A-Za-z.+_-]*$/u.test(version) &&
    !/[<>=~*^|\s]/u.test(version);
}

function addDependency(
  result: Dependency[],
  path: string,
  ecosystem: string,
  name: unknown,
  version: unknown,
): void {
  if (
    typeof name === "string" &&
    name.length > 0 &&
    typeof version === "string" &&
    isExactVersion(version)
  ) {
    result.push({ ecosystem, name, version, path });
  }
}

function safeJson(text: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(text);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function objectEntries(value: unknown): Array<[string, unknown]> {
  return typeof value === "object" && value !== null ? Object.entries(value) : [];
}

function parseNpmJson(path: string, text: string, result: Dependency[]): void {
  const document = safeJson(text);
  if (document === null) return;
  if (path.toLocaleLowerCase("en-US").endsWith("package-lock.json")) {
    for (const [location, metadata] of objectEntries(document.packages)) {
      if (!location.startsWith("node_modules/")) continue;
      const record = typeof metadata === "object" && metadata !== null
        ? (metadata as Record<string, unknown>)
        : {};
      addDependency(result, path, "npm", location.slice("node_modules/".length), record.version);
    }
    for (const [name, metadata] of objectEntries(document.dependencies)) {
      const record = typeof metadata === "object" && metadata !== null
        ? (metadata as Record<string, unknown>)
        : {};
      addDependency(result, path, "npm", name, record.version);
    }
    return;
  }
  for (const section of ["dependencies", "devDependencies", "optionalDependencies"] as const) {
    for (const [name, version] of objectEntries(document[section])) {
      addDependency(result, path, "npm", name, version);
    }
  }
}

function parsePython(path: string, text: string, result: Dependency[]): void {
  const lower = path.toLocaleLowerCase("en-US");
  if (lower.endsWith("pipfile.lock")) {
    const document = safeJson(text);
    if (document === null) return;
    for (const section of ["default", "develop"] as const) {
      for (const [name, metadata] of objectEntries(document[section])) {
        const record = typeof metadata === "object" && metadata !== null
          ? (metadata as Record<string, unknown>)
          : {};
        const version = typeof record.version === "string" ? record.version.replace(/^==/u, "") : record.version;
        addDependency(result, path, "PyPI", name, version);
      }
    }
    return;
  }
  if (lower.endsWith("poetry.lock") || lower.endsWith("uv.lock")) {
    parseTomlPackageBlocks(path, text, "PyPI", result);
    return;
  }
  for (const line of text.split(/\r?\n/u)) {
    const match = /^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([A-Za-z0-9.+_-]+)\s*(?:#.*)?$/u.exec(line);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      addDependency(result, path, "PyPI", match[1], match[2]);
    }
  }
}

function parseTomlPackageBlocks(
  path: string,
  text: string,
  ecosystem: string,
  result: Dependency[],
): void {
  for (const block of text.split(/\[\[package\]\]/u).slice(1)) {
    const name = /^\s*name\s*=\s*"([^"]+)"/mu.exec(block)?.[1];
    const version = /^\s*version\s*=\s*"([^"]+)"/mu.exec(block)?.[1];
    addDependency(result, path, ecosystem, name, version);
  }
}

function parseGo(path: string, text: string, result: Dependency[]): void {
  for (const line of text.split(/\r?\n/u)) {
    const match = /^\s*([^\s()]+)\s+(v[0-9][^\s]*)/u.exec(line.replace(/^\s*require\s+/u, ""));
    if (match?.[1] !== undefined && match[2] !== undefined) {
      addDependency(result, path, "Go", match[1], match[2]);
    }
  }
}

function parseCargoToml(path: string, text: string, result: Dependency[]): void {
  let inDependencies = false;
  for (const line of text.split(/\r?\n/u)) {
    const section = /^\s*\[([^\]]+)\]\s*$/u.exec(line)?.[1];
    if (section !== undefined) {
      inDependencies = /(?:^|\.)dependencies$/u.test(section);
      continue;
    }
    if (!inDependencies) continue;
    const simple = /^\s*([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/u.exec(line);
    if (simple?.[1] !== undefined) {
      addDependency(result, path, "crates.io", simple[1], simple[2]);
      continue;
    }
    const detailed = /^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^}]*\bversion\s*=\s*"([^"]+)"/u.exec(line);
    if (detailed?.[1] !== undefined) {
      addDependency(result, path, "crates.io", detailed[1], detailed[2]);
    }
  }
}

function parsePyproject(path: string, text: string, result: Dependency[]): void {
  const pepDependency = /["']([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([A-Za-z0-9.+_-]+)["']/gu;
  for (const match of text.matchAll(pepDependency)) {
    addDependency(result, path, "PyPI", match[1], match[2]);
  }

  let inPoetryDependencies = false;
  for (const line of text.split(/\r?\n/u)) {
    const section = /^\s*\[([^\]]+)\]\s*$/u.exec(line)?.[1];
    if (section !== undefined) {
      inPoetryDependencies = section === "tool.poetry.dependencies";
      continue;
    }
    if (!inPoetryDependencies) continue;
    const dependency = /^\s*([A-Za-z0-9_.-]+)\s*=\s*"([^"]+)"/u.exec(line);
    if (dependency?.[1] !== undefined && dependency[1] !== "python") {
      addDependency(result, path, "PyPI", dependency[1], dependency[2]);
    }
  }
}

function parseGemfile(path: string, text: string, result: Dependency[]): void {
  for (const line of text.split(/\r?\n/u)) {
    const match = /^\s{4}([^\s(]+) \(([^),\s]+)(?:,[^)]+)?\)$/u.exec(line);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      addDependency(result, path, "RubyGems", match[1], match[2]);
    }
  }
}

function parseMaven(path: string, text: string, result: Dependency[]): void {
  const dependency = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>[\s\S]*?<\/dependency>/gu;
  for (const match of text.matchAll(dependency)) {
    if (match[1] !== undefined && match[2] !== undefined) {
      addDependency(result, path, "Maven", `${match[1]}:${match[2]}`, match[3]);
    }
  }
}

function parseGradle(path: string, text: string, result: Dependency[]): void {
  for (const line of text.split(/\r?\n/u)) {
    const match = /^([^:\s]+):([^:\s]+):([^=\s]+)=/u.exec(line);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      addDependency(result, path, "Maven", `${match[1]}:${match[2]}`, match[3]);
    }
  }
}

function parseComposer(path: string, text: string, result: Dependency[]): void {
  const document = safeJson(text);
  if (document === null) return;
  for (const section of ["packages", "packages-dev"] as const) {
    if (!Array.isArray(document[section])) continue;
    for (const item of document[section]) {
      const record = typeof item === "object" && item !== null ? (item as Record<string, unknown>) : {};
      addDependency(result, path, "Packagist", record.name, record.version);
    }
  }
}

function parseNuget(path: string, text: string, result: Dependency[]): void {
  const document = safeJson(text);
  if (document === null) return;
  for (const [, target] of objectEntries(document.dependencies)) {
    for (const [name, metadata] of objectEntries(target)) {
      const record = typeof metadata === "object" && metadata !== null
        ? (metadata as Record<string, unknown>)
        : {};
      addDependency(result, path, "NuGet", name, record.resolved);
    }
  }
}

function parsePnpm(path: string, text: string, result: Dependency[]): void {
  const entry = /^\s{2,}["']?\/?(@?[^@:\s"']+(?:\/[^@:\s"']+)?)@([^:\s"']+)["']?:/gmu;
  for (const match of text.matchAll(entry)) {
    addDependency(result, path, "npm", match[1], match[2]);
  }
}

function parseYarn(path: string, text: string, result: Dependency[]): void {
  const entry = /^(?:"?)(@?[^@\s"']+(?:\/[^@\s"']+)?)@[^:\n]+:"?\r?\n\s+version\s+"([^"]+)"/gmu;
  for (const match of text.matchAll(entry)) {
    addDependency(result, path, "npm", match[1], match[2]);
  }
}

export function parseDependencies(path: string, bytes: Uint8Array): Dependency[] {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lower = path.toLocaleLowerCase("en-US");
  const result: Dependency[] = [];
  if (lower.endsWith("package-lock.json") || lower.endsWith("package.json")) {
    parseNpmJson(path, text, result);
  } else if (lower.endsWith("pnpm-lock.yaml")) {
    parsePnpm(path, text, result);
  } else if (lower.endsWith("yarn.lock")) {
    parseYarn(path, text, result);
  } else if (lower.endsWith("pyproject.toml")) {
    parsePyproject(path, text, result);
  } else if (
    /(?:requirements(?:-[^/]*)?\.txt|pipfile\.lock|poetry\.lock|uv\.lock)$/u.test(lower)
  ) {
    parsePython(path, text, result);
  } else if (lower.endsWith("go.mod") || lower.endsWith("go.sum")) {
    parseGo(path, text, result);
  } else if (lower.endsWith("cargo.lock")) {
    parseTomlPackageBlocks(path, text, "crates.io", result);
  } else if (lower.endsWith("cargo.toml")) {
    parseCargoToml(path, text, result);
  } else if (lower.endsWith("gemfile.lock")) {
    parseGemfile(path, text, result);
  } else if (lower.endsWith("pom.xml")) {
    parseMaven(path, text, result);
  } else if (lower.endsWith("gradle.lockfile")) {
    parseGradle(path, text, result);
  } else if (lower.endsWith("composer.lock")) {
    parseComposer(path, text, result);
  } else if (lower.endsWith("packages.lock.json")) {
    parseNuget(path, text, result);
  }
  const unique = new Map(result.map((dependency) => [
    `${dependency.ecosystem}\u0000${dependency.name}\u0000${dependency.version}`,
    dependency,
  ]));
  return [...unique.values()];
}

export interface OsvQuery {
  package: { ecosystem: string; name: string };
  version: string;
}

export interface OsvBatchRequest {
  queries: OsvQuery[];
}

export interface OsvBatchResponse {
  results: Array<{ vulns?: Array<{ id: string; summary?: string }> }>;
}

export interface OsvTransport {
  queryBatch(request: OsvBatchRequest): Promise<OsvBatchResponse>;
}

export interface DependencyFindingDraft {
  category: "vulnerable_dependency";
  ecosystem: string;
  package: string;
  version: string;
  advisoryId: string;
  summary?: string;
  path: string;
}

export async function correlateOsv(
  dependencies: readonly Dependency[],
  transport: OsvTransport,
): Promise<DependencyFindingDraft[]> {
  const findings: DependencyFindingDraft[] = [];
  for (let offset = 0; offset < dependencies.length; offset += 100) {
    const batch = dependencies.slice(offset, offset + 100);
    const response = await transport.queryBatch({
      queries: batch.map((dependency) => ({
        package: { ecosystem: dependency.ecosystem, name: dependency.name },
        version: dependency.version,
      })),
    });
    for (let index = 0; index < batch.length; index += 1) {
      const dependency = batch[index];
      const result = response.results[index];
      if (dependency === undefined || result?.vulns === undefined) continue;
      for (const vulnerability of result.vulns) {
        if (!vulnerability.id) continue;
        findings.push({
          category: "vulnerable_dependency",
          ecosystem: dependency.ecosystem,
          package: dependency.name,
          version: dependency.version,
          advisoryId: vulnerability.id,
          ...(vulnerability.summary === undefined ? {} : { summary: vulnerability.summary }),
          path: dependency.path,
        });
      }
    }
  }
  return findings;
}

export interface ConfigurationFindingDraft {
  category: "configuration";
  ruleId: string;
  severity: "critical" | "high" | "medium";
  path: string;
  line: number;
}

function findLine(lines: readonly string[], predicate: (line: string) => boolean): number {
  const index = lines.findIndex(predicate);
  return index < 0 ? 1 : index + 1;
}

function addConfigurationFinding(
  findings: ConfigurationFindingDraft[],
  path: string,
  ruleId: string,
  severity: ConfigurationFindingDraft["severity"],
  line: number,
): void {
  findings.push({ category: "configuration", ruleId, severity, path, line });
}

function scanWorkflow(
  path: string,
  text: string,
  lines: readonly string[],
  findings: ConfigurationFindingDraft[],
): void {
  const pullTargetLine = findLine(lines, (line) => /(?:^|:)\s*pull_request_target\s*:?\s*$/u.test(line));
  if (/\bpull_request_target\b/u.test(text)) {
    addConfigurationFinding(
      findings,
      path,
      "github_actions.pull_request_target",
      "high",
      pullTargetLine,
    );
  }
  const writeAllLine = findLine(lines, (line) => /^\s*permissions\s*:\s*write-all\s*$/u.test(line));
  if (lines.some((line) => /^\s*permissions\s*:\s*write-all\s*$/u.test(line))) {
    addConfigurationFinding(
      findings,
      path,
      "github_actions.write_all_permissions",
      "high",
      writeAllLine,
    );
  }
  const unpinnedLine = findLine(lines, (line) => {
    const match = /\buses\s*:\s*([^\s@]+)@([^\s#]+)/u.exec(line);
    return match !== null && !/^[a-f0-9]{40}$/iu.test(match[2] ?? "");
  });
  if (
    lines.some((line) => {
      const match = /\buses\s*:\s*([^\s@]+)@([^\s#]+)/u.exec(line);
      return match !== null && !/^[a-f0-9]{40}$/iu.test(match[2] ?? "");
    })
  ) {
    addConfigurationFinding(
      findings,
      path,
      "github_actions.unpinned_action",
      "medium",
      unpinnedLine,
    );
  }
  const secretShellLine = findLine(
    lines,
    (line) => /\brun\s*:/u.test(line) && /\$\{\{\s*secrets\./u.test(line),
  );
  if (lines.some((line) => /\brun\s*:/u.test(line) && /\$\{\{\s*secrets\./u.test(line))) {
    addConfigurationFinding(
      findings,
      path,
      "github_actions.secret_in_shell",
      "high",
      secretShellLine,
    );
  }
}

function scanDocker(
  path: string,
  lines: readonly string[],
  findings: ConfigurationFindingDraft[],
): void {
  const secretLine = findLine(
    lines,
    (line) => /^\s*(?:ARG|ENV)\s+[^\s=]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)/iu.test(line),
  );
  if (
    lines.some((line) =>
      /^\s*(?:ARG|ENV)\s+[^\s=]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)/iu.test(line),
    )
  ) {
    addConfigurationFinding(findings, path, "docker.secret_in_arg_env", "high", secretLine);
  }
  const pipeShellLine = findLine(
    lines,
    (line) => /^\s*RUN\b/iu.test(line) && /\b(?:curl|wget)\b[\s\S]*\|\s*(?:sh|bash)\b/iu.test(line),
  );
  if (
    lines.some(
      (line) => /^\s*RUN\b/iu.test(line) && /\b(?:curl|wget)\b[\s\S]*\|\s*(?:sh|bash)\b/iu.test(line),
    )
  ) {
    addConfigurationFinding(findings, path, "docker.download_pipe_shell", "high", pipeShellLine);
  }
  const writableLine = findLine(lines, (line) => /^\s*RUN\b[\s\S]*\bchmod\s+(?:-R\s+)?777\b/iu.test(line));
  if (lines.some((line) => /^\s*RUN\b[\s\S]*\bchmod\s+(?:-R\s+)?777\b/iu.test(line))) {
    addConfigurationFinding(findings, path, "docker.world_writable", "medium", writableLine);
  }
  const users = lines.filter((line) => /^\s*USER\s+/iu.test(line));
  if (users.length === 0 || users.some((line) => /^\s*USER\s+(?:0|root)\s*$/iu.test(line))) {
    const rootLine = users.length === 0 ? 1 : findLine(lines, (line) => /^\s*USER\s+(?:0|root)\s*$/iu.test(line));
    addConfigurationFinding(findings, path, "docker.root_user", "medium", rootLine);
  }
}

function scanTerraform(
  path: string,
  text: string,
  lines: readonly string[],
  findings: ConfigurationFindingDraft[],
): void {
  const publicNetwork = /(?:0\.0\.0\.0\/0|::\/0)/u.test(text);
  const sensitivePort = /(?:from_port|to_port)\s*=\s*(?:22|3306|5432|6379|9200|27017)\b/u.test(text);
  if (publicNetwork && sensitivePort) {
    addConfigurationFinding(
      findings,
      path,
      "terraform.public_sensitive_ingress",
      "critical",
      findLine(lines, (line) => /(?:0\.0\.0\.0\/0|::\/0)/u.test(line)),
    );
  }
  if (/\bacl\s*=\s*"public-(?:read|read-write)"/u.test(text) || /public_access\s*=\s*true/u.test(text)) {
    addConfigurationFinding(
      findings,
      path,
      "terraform.public_storage",
      "high",
      findLine(lines, (line) => /public-(?:read|read-write)|public_access\s*=\s*true/u.test(line)),
    );
  }
}

function scanKubernetes(
  path: string,
  lines: readonly string[],
  findings: ConfigurationFindingDraft[],
): void {
  const privilegedLine = findLine(lines, (line) => /^\s*privileged\s*:\s*true\s*$/iu.test(line));
  if (lines.some((line) => /^\s*privileged\s*:\s*true\s*$/iu.test(line))) {
    addConfigurationFinding(findings, path, "kubernetes.privileged_container", "critical", privilegedLine);
  }
  const escalationLine = findLine(
    lines,
    (line) => /^\s*allowPrivilegeEscalation\s*:\s*true\s*$/iu.test(line),
  );
  if (lines.some((line) => /^\s*allowPrivilegeEscalation\s*:\s*true\s*$/iu.test(line))) {
    addConfigurationFinding(findings, path, "kubernetes.privilege_escalation", "high", escalationLine);
  }
}

function scanTlsAndCors(
  path: string,
  text: string,
  lines: readonly string[],
  findings: ConfigurationFindingDraft[],
): void {
  if (/rejectUnauthorized\s*:\s*false|verify\s*=\s*false|CERT_NONE/u.test(text)) {
    addConfigurationFinding(
      findings,
      path,
      "tls.verification_disabled",
      "high",
      findLine(lines, (line) => /rejectUnauthorized\s*:\s*false|verify\s*=\s*false|CERT_NONE/u.test(line)),
    );
  }
  const wildcardOrigin = /origin\s*:\s*["']\*["']/u.test(text);
  const credentials = /credentials\s*:\s*true/u.test(text);
  if (wildcardOrigin && credentials) {
    addConfigurationFinding(
      findings,
      path,
      "cors.wildcard_credentials",
      "high",
      findLine(lines, (line) => /origin\s*:\s*["']\*["']/u.test(line)),
    );
  }
}

export function scanConfiguration(files: readonly AnalyzerFile[]): ConfigurationFindingDraft[] {
  const findings: ConfigurationFindingDraft[] = [];
  for (const file of files) {
    const lower = file.path.toLocaleLowerCase("en-US");
    const text = new TextDecoder("utf-8", { fatal: false }).decode(file.bytes);
    const lines = text.split(/\r?\n/u);
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/u.test(lower)) {
      scanWorkflow(file.path, text, lines, findings);
    }
    if (/(?:^|\/)dockerfile(?:\.[^/]*)?$/u.test(lower)) {
      scanDocker(file.path, lines, findings);
    }
    if (lower.endsWith(".tf") || lower.endsWith(".tfvars")) {
      scanTerraform(file.path, text, lines, findings);
    }
    if (
      /(?:^|\/)(?:deployment[^/]*|statefulset[^/]*|daemonset[^/]*|pod[^/]*|kustomization|values)\.ya?ml$/u.test(lower) ||
      lower.includes("k8s/") ||
      lower.includes("kubernetes/")
    ) {
      scanKubernetes(file.path, lines, findings);
    }
    scanTlsAndCors(file.path, text, lines, findings);
  }
  return findings;
}
