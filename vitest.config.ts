import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/**/*.test.ts", "apps/**/*.test.ts"],
    coverage: {
      include: [
        "packages/**/src/**/*.ts",
        "apps/worker/src/runtime.ts",
        "apps/worker/src/index.ts",
        "apps/api/src/index.ts",
        "apps/api/src/system-metrics.ts",
      ],
      exclude: ["**/*.test.ts", "**/*.d.ts"],
      provider: "v8",
      reporter: ["text", "json-summary"],
      thresholds: {
        branches: 90,
        functions: 90,
        lines: 90,
        statements: 90,
      },
    },
  },
});
