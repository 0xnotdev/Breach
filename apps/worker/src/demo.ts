import { readFile } from "node:fs/promises";
import { runControlledDemo } from "./runtime.js";

const fixture = await readFile(new URL("../../../fixtures/canary-repository/credential.txt", import.meta.url), "utf8");
const raw = fixture.slice(fixture.indexOf("=") + 1).trim();
const result = await runControlledDemo(raw);
process.stdout.write(`${JSON.stringify(result)}\n`);
