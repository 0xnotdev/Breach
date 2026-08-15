import { XMLParser } from "fast-xml-parser";
import { parseDocument } from "yaml";

export interface ParseBounds { maxBytes: number; maxDepth: number }

const utf8 = new TextEncoder();
function hasForbiddenControls(text: string): boolean {
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0;
    if ((code < 32 && code !== 9 && code !== 10 && code !== 13) || (code >= 127 && code <= 159)) return true;
  }
  return false;
}

function assertInput(text: string, bounds: ParseBounds): void {
  if (!Number.isSafeInteger(bounds.maxBytes) || bounds.maxBytes < 1 || utf8.encode(text).byteLength > bounds.maxBytes) throw new Error("Input exceeds byte bound");
  if (!Number.isSafeInteger(bounds.maxDepth) || bounds.maxDepth < 1 || bounds.maxDepth > 64) throw new Error("Invalid depth bound");
  if (hasForbiddenControls(text)) throw new Error("Input contains forbidden control characters");
}

function assertDepth(value: unknown, maxDepth: number): void {
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 1 }];
  const visited = new Set<object>();
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) continue;
    if (current.depth > maxDepth) throw new Error("Parsed structure exceeds depth bound");
    if (typeof current.value !== "object" || current.value === null) continue;
    if (visited.has(current.value)) throw new Error("Cyclic parsed structure denied");
    visited.add(current.value);
    const children = Array.isArray(current.value) ? current.value : Object.values(current.value as Record<string, unknown>);
    for (const child of children) if (typeof child === "object" && child !== null) stack.push({ value: child, depth: current.depth + 1 });
  }
}

export function parseSafeYaml(text: string, bounds: ParseBounds): unknown {
  assertInput(text, bounds);
  if (/(?:^|\s)[&*][A-Za-z0-9_-]+|!!|!<|%TAG/um.test(text)) throw new Error("YAML aliases and custom tags are denied");
  const document = parseDocument(text, { schema: "core", merge: false, prettyErrors: false, strict: true });
  if (document.errors.length > 0) throw new Error("Invalid safe YAML");
  const value: unknown = document.toJS({ maxAliasCount: 0 });
  assertDepth(value, bounds.maxDepth);
  return value;
}

export function parseSafeXml(text: string, bounds: ParseBounds): unknown {
  assertInput(text, bounds);
  if (/<!DOCTYPE|<!ENTITY|\b(?:SYSTEM|PUBLIC)\b/iu.test(text)) throw new Error("XML DTD and entities are denied");
  const parser = new XMLParser({ processEntities: false, ignoreAttributes: false, allowBooleanAttributes: false, parseTagValue: false, trimValues: true });
  const value: unknown = parser.parse(text);
  assertDepth(value, bounds.maxDepth);
  return value;
}

export class EgressPolicy {
  readonly #internalHosts: ReadonlySet<string>;

  constructor({ internalHosts = [] }: { internalHosts?: readonly string[] } = {}) {
    this.#internalHosts = new Set(internalHosts.map((host) => host.toLocaleLowerCase("en-US")));
  }

  assertAllowed(target: string | URL): URL {
    let url: URL;
    try { url = new URL(target); } catch { throw new Error("Egress denied: invalid URL"); }
    const host = url.hostname.toLocaleLowerCase("en-US");
    const serviceAllowed = url.protocol === "https:" && (url.port === "" || url.port === "443") && (host === "api.github.com" || host === "api.osv.dev");
    const internalAllowed = (url.protocol === "http:" || url.protocol === "https:") && this.#internalHosts.has(host);
    if (url.username !== "" || url.password !== "" || (!serviceAllowed && !internalAllowed)) throw new Error("Egress denied: destination is not allowlisted");
    return url;
  }
}

export function escapeUntrustedText(value: string, maxCharacters = 256): string {
  if (!Number.isSafeInteger(maxCharacters) || maxCharacters < 2) throw new Error("Invalid text bound");
  let escaped = "";
  for (const character of value.normalize("NFC")) {
    const code = character.codePointAt(0) ?? 0;
    if (character === "\r") escaped += "\\r";
    else if (character === "\n") escaped += "\\n";
    else if (character === "\t") escaped += "\\t";
    else if (code < 32 || (code >= 127 && code <= 159)) escaped += `\\u{${code.toString(16)}}`;
    else escaped += character;
  }
  const segments = Array.from(new Intl.Segmenter("en", { granularity: "grapheme" }).segment(escaped), ({ segment }) => segment);
  return segments.length <= maxCharacters ? escaped : `${segments.slice(0, maxCharacters - 1).join("")}…`;
}

export type RetentionSurfaces = Readonly<Record<string, string>>;

export class CanaryAuditor {
  constructor(
    readonly rawCanary: string,
    readonly expectedFingerprint: string,
    readonly maximumFingerprintOccurrences = 1,
  ) {
    if (
      rawCanary.length < 16 ||
      !/^[a-f0-9]{64}$/u.test(expectedFingerprint) ||
      !Number.isSafeInteger(maximumFingerprintOccurrences) ||
      maximumFingerprintOccurrences < 1
    ) throw new Error("Invalid canary audit values");
  }

  audit(surfaces: RetentionSurfaces): { rawOccurrences: number; fingerprintOccurrences: number; surfacesChecked: number } {
    const values = Object.values(surfaces);
    const rawOccurrences = values.reduce((count, value) => count + occurrences(value, this.rawCanary), 0);
    const fingerprintOccurrences = values.reduce((count, value) => count + occurrences(value, this.expectedFingerprint), 0);
    if (rawOccurrences !== 0) throw new Error("Raw canary retained in audited surface");
    if (fingerprintOccurrences < 1 || fingerprintOccurrences > this.maximumFingerprintOccurrences) {
      throw new Error(`Expected between one and ${String(this.maximumFingerprintOccurrences)} fingerprints, observed ${String(fingerprintOccurrences)}`);
    }
    return { rawOccurrences, fingerprintOccurrences, surfacesChecked: values.length };
  }
}

function occurrences(haystack: string, needle: string): number {
  let count = 0;
  let offset = 0;
  while ((offset = haystack.indexOf(needle, offset)) !== -1) { count += 1; offset += needle.length; }
  return count;
}
