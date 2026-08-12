import { runControlledDemo } from "./runtime.js";

const result = await runControlledDemo();
process.stdout.write(`${JSON.stringify(result)}\n`);
