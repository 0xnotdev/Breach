import { describe, expect, it, vi } from "vitest";
import { PassiveExploitabilityAnalyzer } from "./index.js";

const file = (path: string, source: string) => ({ path, bytes: new TextEncoder().encode(source) });

describe("bounded passive exploitability analysis", () => {
  it("reconstructs a cross-file Express source-to-command path", () => {
    const result = new PassiveExploitabilityAnalyzer().analyze([
      file(
        "routes/render.ts",
        'import { renderController } from "../controllers/render";\nrouter.post("/render", (req, res) => renderController(req.body.filename));',
      ),
      file(
        "controllers/render.ts",
        'import { render } from "../services/image";\nexport function renderController(filename: string) { return render(filename); }',
      ),
      file(
        "services/image.ts",
        "export function render(filename: string) { return child_process.exec(`convert ${filename}`); }",
      ),
    ]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      category: "command_injection",
      cwe: "CWE-78",
      severity: "critical",
      score: 100,
      level: "high_confidence_static_path",
      entryPoint: "POST /render",
      attackerSourceIdentified: true,
      completeDataflowObserved: true,
      sanitizerObserved: false,
      authBarrierObserved: false,
      runtimeVerified: false,
      activeTestingPerformed: false,
      deploymentConfirmed: false,
    });
    expect(result.findings[0]?.path.map((node) => node.role)).toEqual([
      "entry",
      "source",
      "flow",
      "flow",
      "sink",
    ]);
    expect(JSON.stringify(result)).not.toContain("convert ${filename}");
  });

  it("reconstructs a cross-file FastAPI parameter-to-SSRF path", () => {
    const result = new PassiveExploitabilityAnalyzer().analyze([
      file(
        "app.py",
        'from client import download\n@app.get("/fetch")\ndef fetch(url: str):\n    return download(url)\n',
      ),
      file("client.py", "def download(url):\n    return requests.get(url)\n"),
    ]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      category: "ssrf",
      cwe: "CWE-918",
      score: 100,
      level: "high_confidence_static_path",
      entryPoint: "GET /fetch",
      completeDataflowObserved: true,
    });
  });

  it("does not connect unrelated functions that share a symbol name", () => {
    const result = new PassiveExploitabilityAnalyzer().analyze([
      file("routes/run.ts", 'router.post("/run", (req, res) => run(req.body.command));'),
      file("admin/run.ts", "export function run(command: string) { return exec(command); }"),
      file("jobs/run.ts", "export function run(command: string) { return exec(command); }"),
    ]);

    expect(result.findings.filter((finding) => finding.completeDataflowObserved)).toEqual([]);
    expect(result.findings.filter((finding) => finding.level === "possible")).toHaveLength(2);
  });

  it("models async FastAPI handlers without executing Python", () => {
    const result = new PassiveExploitabilityAnalyzer().analyze([
      file("app.py", '@app.post("/fetch")\nasync def fetch(url: str):\n    return requests.get(url)\n'),
    ]);

    expect(result.findings).toContainEqual(expect.objectContaining({ category: "ssrf", entryPoint: "POST /fetch", completeDataflowObserved: true }));
  });

  it("downranks a same-function path with sanitizer and authentication barriers", () => {
    const result = new PassiveExploitabilityAnalyzer().analyze([
      file(
        "routes/files.ts",
        'router.get("/files/:name", requireAuth, (req, res) => {\n' +
          "  const safe = path.basename(req.params.name);\n" +
          "  return fs.readFile(safe);\n" +
          "});\n",
      ),
    ]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      category: "path_traversal",
      score: 65,
      level: "plausible",
      sanitizerObserved: true,
      authBarrierObserved: true,
      completeDataflowObserved: true,
    });
  });

  it("does not report a parameterized SQL query as injection", () => {
    const result = new PassiveExploitabilityAnalyzer().analyze([
      file(
        "routes/search.ts",
        'router.get("/search", (req, res) => db.query("SELECT * FROM users WHERE id = ?", [req.query.id]));',
      ),
    ]);

    expect(result.findings.filter((finding) => finding.category === "sql_injection")).toEqual([]);
  });

  it("keeps a disconnected dangerous primitive in the possible tier", () => {
    const result = new PassiveExploitabilityAnalyzer().analyze([
      file("utils/shell.ts", "export function run(command: string) { return exec(command); }"),
    ]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      category: "command_injection",
      score: 10,
      level: "possible",
      attackerSourceIdentified: false,
      completeDataflowObserved: false,
    });
  });

  it("models Next route handlers and Flask route decorators", () => {
    const nextResult = new PassiveExploitabilityAnalyzer().analyze([
      file(
        "app/api/run/route.ts",
        "export async function POST(request: Request) {\n" +
          "  const body = await request.json();\n" +
          "  return run(body.command);\n" +
          "}\n" +
          "function run(command: string) { return exec(command); }\n",
      ),
    ]);
    const flaskResult = new PassiveExploitabilityAnalyzer().analyze([
      file(
        "app.py",
        '@app.route("/fetch", methods=["POST"])\n' +
          "def fetch():\n" +
          '    url = request.args.get("url")\n' +
          "    return download(url)\n\n" +
          "def download(url):\n" +
          "    return requests.get(url)\n",
      ),
    ]);

    expect(nextResult.findings[0]).toMatchObject({
      category: "command_injection",
      entryPoint: "POST /api/run",
      level: "high_confidence_static_path",
    });
    expect(flaskResult.findings[0]).toMatchObject({
      category: "ssrf",
      entryPoint: "POST /fetch",
      level: "high_confidence_static_path",
    });
  });

  it("models Next form-data and URL search-parameter sources", () => {
    const form = new PassiveExploitabilityAnalyzer().analyze([
      file("app/api/run/route.ts", 'export async function POST(request: Request) { const data = await request.formData(); return exec(data.get("command")); }'),
    ]);
    const query = new PassiveExploitabilityAnalyzer().analyze([
      file("app/api/fetch/route.ts", 'export function GET(request: Request) { const url = new URL(request.url); return fetch(url.searchParams.get("target")); }'),
    ]);

    expect(form.findings).toContainEqual(expect.objectContaining({ category: "command_injection", completeDataflowObserved: true }));
    expect(query.findings).toContainEqual(expect.objectContaining({ category: "ssrf", completeDataflowObserved: true }));
  });

  it("classifies SQL, dynamic-code, and unsafe-deserialization sinks", () => {
    const result = new PassiveExploitabilityAnalyzer().analyze([
      file(
        "routes/risky.ts",
        'router.get("/sql", (req, res) => db.query(`SELECT * FROM t WHERE id = ${req.query.id}`));\n' +
          'router.post("/evaluate", (req, res) => eval(req.body.code));\n' +
          'router.post("/load", (req, res) => deserialize(req.body.value));\n',
      ),
    ]);

    expect(result.findings.map((finding) => finding.category)).toEqual([
      "sql_injection",
      "code_injection",
      "unsafe_deserialization",
    ]);
    expect(result.findings[0]).toMatchObject({ score: 85, level: "probable" });
  });

  it("stops cross-function traversal at the configured graph depth", () => {
    const result = new PassiveExploitabilityAnalyzer({
      maxFiles: 10,
      maxGraphNodes: 1_000,
      maxDepth: 1,
      timeoutMs: 1_000,
    }).analyze([
      file(
        "routes/deep.ts",
        'router.post("/deep", (req, res) => first(req.body.value));\n' +
          "function first(value: string) { return second(value); }\n" +
          "function second(value: string) { return exec(value); }\n",
      ),
    ]);

    expect(result.diagnostics).toMatchObject({ partial: true });
    expect(result.diagnostics.reasons).toContain("graph_depth_limit");
    expect(result.findings).toContainEqual(
      expect.objectContaining({ level: "possible", completeDataflowObserved: false }),
    );
  });

  it("models JavaScript syntax variants, dynamic Next routes, and Python import aliases", () => {
    const next = new PassiveExploitabilityAnalyzer().analyze([
      file("app/api/files/[name]/route.tsx", "export function DELETE(request: Request) { return exec(request); }"),
      file("components/helper.jsx", "const helper = function(value) { return eval(value); };"),
      file("scripts/helper.js", "function disconnected(value) { return deserialize(value); }"),
    ]);
    expect(next.findings).toContainEqual(expect.objectContaining({ category: "command_injection", entryPoint: "DELETE /api/files/:name" }));
    expect(next.findings).toContainEqual(expect.objectContaining({ category: "code_injection", level: "possible" }));
    expect(next.findings).toContainEqual(expect.objectContaining({ category: "unsafe_deserialization", level: "possible" }));

    const python = new PassiveExploitabilityAnalyzer().analyze([
      file("routes.py", 'from service import download as fetch_remote\n@app.route("/proxy")\ndef proxy():\n    url = request.args.get("url")\n    return fetch_remote(url)\n'),
      file("service.py", "def download(url):\n    return requests.get(url)\n"),
    ]);
    expect(python.findings).toContainEqual(expect.objectContaining({ category: "ssrf", entryPoint: "GET /proxy", completeDataflowObserved: true }));
  });

  it("reports invalid and exhausted analysis budgets deterministically", () => {
    expect(() => new PassiveExploitabilityAnalyzer({ maxFiles: 0, maxGraphNodes: 1, maxDepth: 1, timeoutMs: 1 })).toThrow("positive");
    const fileLimited = new PassiveExploitabilityAnalyzer({ maxFiles: 1, maxGraphNodes: 1_000, maxDepth: 10, timeoutMs: 1_000 }).analyze([
      file("one.ts", "function one() { return 1; }"),
      file("two.ts", "function two() { return 2; }"),
    ]);
    expect(fileLimited.diagnostics.reasons).toContain("file_limit");
    const graphLimited = new PassiveExploitabilityAnalyzer({ maxFiles: 2, maxGraphNodes: 1, maxDepth: 10, timeoutMs: 1_000 }).analyze([
      file("route.ts", 'router.get("/", (req, res) => exec(req.query.value));'),
    ]);
    expect(graphLimited.diagnostics.reasons).toContain("graph_node_limit");

    const clock = vi.spyOn(performance, "now").mockReturnValueOnce(0).mockReturnValue(2);
    try {
      const timedOut = new PassiveExploitabilityAnalyzer({ maxFiles: 1, maxGraphNodes: 100, maxDepth: 10, timeoutMs: 1 }).analyze([file("route.ts", "function route() { return 1; }")]);
      expect(timedOut.diagnostics.reasons).toContain("timeout");
    } finally {
      clock.mockRestore();
    }

    const traversalClock = vi.spyOn(performance, "now").mockReturnValueOnce(0).mockReturnValueOnce(0).mockReturnValue(2);
    try {
      const traversalTimeout = new PassiveExploitabilityAnalyzer({ maxFiles: 1, maxGraphNodes: 100, maxDepth: 10, timeoutMs: 1 }).analyze([
        file("route.ts", 'router.post("/run", (req, res) => handlers["run"](req.body.value));'),
      ]);
      expect(traversalTimeout.diagnostics.reasons).toContain("timeout");
    } finally {
      traversalClock.mockRestore();
    }
  });
});
