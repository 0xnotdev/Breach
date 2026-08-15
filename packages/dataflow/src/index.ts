import ts from "typescript";
import { posix as pathPosix } from "node:path";
import {
  classifyExploitabilityLevel,
  type ExploitabilityLevel,
} from "@breach/contracts";

export interface SourceFileInput {
  readonly path: string;
  readonly bytes: Uint8Array;
}

export interface AttackPathNode {
  readonly file: string;
  readonly line: number;
  readonly role: "entry" | "source" | "flow" | "sanitizer" | "auth" | "sink";
  readonly symbol?: string;
  readonly edge?: "route" | "argument" | "return" | "call" | "assignment";
}

export interface AttackPathFinding {
  readonly category:
    | "command_injection"
    | "sql_injection"
    | "ssrf"
    | "path_traversal"
    | "code_injection"
    | "unsafe_deserialization";
  readonly cwe: string;
  readonly severity: "critical" | "high";
  readonly score: number;
  readonly level: ExploitabilityLevel;
  readonly entryPoint?: string;
  readonly attackerSourceIdentified: boolean;
  readonly completeDataflowObserved: boolean;
  readonly sanitizerObserved: boolean;
  readonly authBarrierObserved: boolean;
  readonly runtimeVerified: false;
  readonly activeTestingPerformed: false;
  readonly deploymentConfirmed: false;
  readonly path: readonly AttackPathNode[];
}

export interface AnalysisDiagnostics {
  readonly filesParsed: number;
  readonly graphNodes: number;
  readonly partial: boolean;
  readonly reasons: readonly string[];
}

export interface PassiveAnalysisResult {
  readonly findings: readonly AttackPathFinding[];
  readonly diagnostics: AnalysisDiagnostics;
}

export interface DataflowBudgets {
  readonly maxFiles: number;
  readonly maxGraphNodes: number;
  readonly maxDepth: number;
  readonly timeoutMs: number;
}

interface CallModel {
  readonly callee: string;
  readonly target: string;
  readonly args: readonly string[];
  readonly line: number;
  readonly sink: SinkKind | null;
  readonly parameterizedSql: boolean;
}

interface AssignmentModel {
  readonly name: string;
  readonly expression: string;
  readonly line: number;
  readonly sanitizer: boolean;
}

interface FunctionModel {
  readonly id: string;
  readonly name: string;
  readonly file: string;
  readonly line: number;
  readonly params: readonly string[];
  readonly calls: readonly CallModel[];
  readonly assignments: readonly AssignmentModel[];
  readonly entryPoint?: string;
  readonly entryLine?: number;
  readonly entrySourceParams: readonly string[];
  readonly authBarrier: boolean;
  readonly imports: ReadonlyMap<string, { importedName: string; source: string }>;
}

interface SinkKind {
  readonly category: AttackPathFinding["category"];
  readonly cwe: string;
  readonly severity: AttackPathFinding["severity"];
  readonly symbol: string;
}

interface TraversalState {
  readonly model: FunctionModel;
  readonly tainted: Set<string>;
  readonly path: AttackPathNode[];
  readonly sourceIdentified: boolean;
  readonly sanitizerObserved: boolean;
  readonly authBarrierObserved: boolean;
  readonly depth: number;
}

const defaultBudgets: DataflowBudgets = {
  maxFiles: 500,
  maxGraphNodes: 10_000,
  maxDepth: 12,
  timeoutMs: 2_000,
};

const jsSourcePattern = /\b(?:req|request)\.(?:body|query|params|headers|cookies)(?:\.[A-Za-z_$][\w$]*)?/u;
const pythonSourcePattern = /\brequest\.(?:args|form|json|headers|cookies)(?:\.get\([^)]*\))?/u;
const sanitizerPattern = /(?:^|\.)(?:basename|normalize|resolve|sanitize|escape|validate|clean|quote)$/iu;

function sourceSymbol(expression: string): string | null {
  return jsSourcePattern.exec(expression)?.[0] ?? pythonSourcePattern.exec(expression)?.[0] ?? null;
}

function expressionContainsSymbol(expression: string, symbol: string): boolean {
  const escaped = symbol.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(`\\b${escaped}\\b`, "u").test(expression);
}

function isTaintedExpression(expression: string, tainted: ReadonlySet<string>): boolean {
  if (sourceSymbol(expression) !== null) return true;
  for (const symbol of tainted) {
    if (expressionContainsSymbol(expression, symbol)) return true;
  }
  return false;
}

function sinkFor(callee: string): SinkKind | null {
  const lower = callee.toLocaleLowerCase("en-US");
  if (/(?:^|\.)(?:exec|execsync|spawn|spawnsync|system|popen)$/u.test(lower)) {
    return { category: "command_injection", cwe: "CWE-78", severity: "critical", symbol: callee };
  }
  if (/(?:^|\.)(?:eval|compile)$/u.test(lower) || lower === "exec") {
    return { category: "code_injection", cwe: "CWE-94", severity: "critical", symbol: callee };
  }
  if (/(?:^|\.)(?:query|execute|raw)$/u.test(lower)) {
    return { category: "sql_injection", cwe: "CWE-89", severity: "critical", symbol: callee };
  }
  if (
    /^(?:fetch|axios(?:\.get|\.post)?|requests\.(?:get|post|request)|httpx\.(?:get|post)|urllib\.)/u.test(lower) ||
    /(?:^|\.)http\.(?:get|request)$/u.test(lower)
  ) {
    return { category: "ssrf", cwe: "CWE-918", severity: "high", symbol: callee };
  }
  if (/(?:^|\.)(?:readfile|readfilesync|writefile|writefilesync|open|unlink|createreadstream)$/u.test(lower)) {
    return { category: "path_traversal", cwe: "CWE-22", severity: "high", symbol: callee };
  }
  if (/(?:pickle\.loads|yaml\.load|deserialize|unserialize)$/u.test(lower)) {
    return {
      category: "unsafe_deserialization",
      cwe: "CWE-502",
      severity: "critical",
      symbol: callee,
    };
  }
  return null;
}

function isParameterizedSql(call: { callee: string; args: readonly string[] }): boolean {
  if (!/(?:^|\.)(?:query|execute|raw)$/iu.test(call.callee) || call.args.length < 2) return false;
  const query = call.args[0] ?? "";
  const isLiteral = /^(?:["'`])/.test(query);
  const hasPlaceholder = /(?:\?|\$\d+|:[A-Za-z_][A-Za-z0-9_]*)/u.test(query);
  const hasInterpolation = /\$\{|\+/.test(query);
  return isLiteral && hasPlaceholder && !hasInterpolation;
}

function calleeName(expression: ts.LeftHandSideExpression): string {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return expression.getText();
}

function collectTypeScriptBody(
  sourceFile: ts.SourceFile,
  root: ts.ConciseBody,
  nodeCounter: { value: number },
  maxNodes: number,
): { calls: CallModel[]; assignments: AssignmentModel[] } {
  const calls: CallModel[] = [];
  const assignments: AssignmentModel[] = [];
  const visit = (node: ts.Node): void => {
    if (nodeCounter.value >= maxNodes) return;
    nodeCounter.value += 1;
    if (ts.isCallExpression(node)) {
      const callee = node.expression.getText(sourceFile);
      const call = {
        callee,
        target: calleeName(node.expression),
        args: node.arguments.map((argument) => argument.getText(sourceFile)),
        line: sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1,
      };
      calls.push({
        ...call,
        sink: sinkFor(callee),
        parameterizedSql: isParameterizedSql(call),
      });
    }
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer !== undefined
    ) {
      const expression = node.initializer.getText(sourceFile);
      const initializerCallee = ts.isCallExpression(node.initializer)
        ? node.initializer.expression.getText(sourceFile)
        : "";
      assignments.push({
        name: node.name.text,
        expression,
        line: sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1,
        sanitizer: sanitizerPattern.test(initializerCallee),
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(root);
  return { calls, assignments };
}

function scriptKind(path: string): ts.ScriptKind {
  const lower = path.toLocaleLowerCase("en-US");
  if (lower.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (lower.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (lower.endsWith(".js")) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function parseTypeScript(
  path: string,
  text: string,
  nodeCounter: { value: number },
  maxNodes: number,
): FunctionModel[] {
  const sourceFile = ts.createSourceFile(path, text, ts.ScriptTarget.ESNext, true, scriptKind(path));
  const functions: FunctionModel[] = [];
  const imports = new Map<string, { importedName: string; source: string }>();
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
    const source = statement.moduleSpecifier.text;
    const bindings = statement.importClause?.namedBindings;
    if (bindings !== undefined && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) {
        imports.set(element.name.text, {
          importedName: element.propertyName?.text ?? element.name.text,
          source,
        });
      }
    }
  }
  const register = (
    name: string,
    node: ts.FunctionLikeDeclaration,
    options: {
      entryPoint?: string;
      entryLine?: number;
      authBarrier?: boolean;
      entrySourceParams?: readonly string[];
    } = {},
  ): void => {
    if (node.body === undefined) return;
    const parsed = collectTypeScriptBody(sourceFile, node.body, nodeCounter, maxNodes);
    const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
    functions.push({
      id: `${path}:${String(line)}:${name}`,
      name,
      file: path,
      line,
      params: node.parameters.map((parameter) => parameter.name.getText(sourceFile)),
      calls: parsed.calls,
      assignments: parsed.assignments,
      ...(options.entryPoint === undefined ? {} : { entryPoint: options.entryPoint }),
      ...(options.entryLine === undefined ? {} : { entryLine: options.entryLine }),
      entrySourceParams: options.entrySourceParams ?? [],
      authBarrier: options.authBarrier ?? false,
      imports,
    });
  };

  const visit = (node: ts.Node): void => {
    if (nodeCounter.value >= maxNodes) return;
    nodeCounter.value += 1;
    if (ts.isFunctionDeclaration(node) && node.name !== undefined) {
      const method = node.name.text.toLocaleUpperCase("en-US");
      const routeMatch = /(?:^|\/)app\/(.+)\/route\.[jt]sx?$/u.exec(path.replaceAll("\\", "/"));
      const routeSegment = routeMatch?.[1];
      if (
        routeSegment !== undefined &&
        new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]).has(method)
      ) {
        const routePath = `/${routeSegment}`.replace(/\[([^\]]+)\]/gu, ":$1");
        const firstParameter = node.parameters[0]?.name.getText(sourceFile);
        register(node.name.text, node, {
          entryPoint: `${method} ${routePath}`,
          entryLine: sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1,
          entrySourceParams: firstParameter === undefined ? [] : [firstParameter],
        });
      } else {
        register(node.name.text, node);
      }
    } else if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer !== undefined &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      register(node.name.text, node.initializer);
    }
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const method = node.expression.name.text.toLocaleLowerCase("en-US");
      const routeMethods = new Set(["get", "post", "put", "patch", "delete"]);
      const route = node.arguments[0];
      const handler = node.arguments.at(-1);
      if (
        routeMethods.has(method) &&
        route !== undefined &&
        (ts.isStringLiteral(route) || ts.isNoSubstitutionTemplateLiteral(route)) &&
        handler !== undefined &&
        (ts.isArrowFunction(handler) || ts.isFunctionExpression(handler))
      ) {
        const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
        const middleware = node.arguments.slice(1, -1).map((argument) => argument.getText(sourceFile));
        register(`route:${method}:${route.text}`, handler, {
          entryPoint: `${method.toLocaleUpperCase("en-US")} ${route.text}`,
          entryLine: line,
          authBarrier: middleware.some((item) => /auth|authorize|requireuser|requirelogin/iu.test(item)),
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return functions;
}

function leadingSpaces(line: string): number {
  let result = 0;
  while (result < line.length && line.charCodeAt(result) === 32) result += 1;
  return result;
}

function splitArguments(value: string): string[] {
  return value.split(",").map((part) => part.trim()).filter(Boolean);
}

function parsePython(
  path: string,
  text: string,
  nodeCounter: { value: number },
  maxNodes: number,
): FunctionModel[] {
  const lines = text.split(/\r?\n/u);
  const functions: FunctionModel[] = [];
  const imports = new Map<string, { importedName: string; source: string }>();
  for (const line of lines) {
    const imported = /^\s*from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import\s+(.+)$/u.exec(line);
    if (imported?.[1] === undefined || imported[2] === undefined) continue;
    for (const item of imported[2].split(",")) {
      const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$/u.exec(item);
      if (match?.[1] !== undefined) {
        imports.set(match[2] ?? match[1], { importedName: match[1], source: imported[1] });
      }
    }
  }
  let decorators: Array<{ text: string; line: number }> = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (nodeCounter.value >= maxNodes) break;
    nodeCounter.value += 1;
    const line = lines[index] ?? "";
    if (/^\s*@/u.test(line)) {
      decorators.push({ text: line.trim(), line: index + 1 });
      continue;
    }
    const definition = /^(\s*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*:/u.exec(line);
    if (definition === null || definition[2] === undefined) {
      if (line.trim().length > 0) decorators = [];
      continue;
    }
    const indent = definition[1]?.length ?? 0;
    const name = definition[2];
    const params = splitArguments(definition[3] ?? "").map((parameter) =>
      parameter.split(/[:=]/u)[0]?.trim() ?? "",
    ).filter(Boolean);
    let end = index + 1;
    while (end < lines.length) {
      const candidate = lines[end] ?? "";
      if (candidate.trim().length > 0 && leadingSpaces(candidate) <= indent) break;
      end += 1;
    }
    const bodyLines = lines.slice(index + 1, end);
    const calls: CallModel[] = [];
    const assignments: AssignmentModel[] = [];
    for (let offset = 0; offset < bodyLines.length; offset += 1) {
      if (nodeCounter.value >= maxNodes) break;
      nodeCounter.value += 1;
      const bodyLine = bodyLines[offset] ?? "";
      const lineNumber = index + offset + 2;
      const assignment = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/u.exec(bodyLine);
      if (assignment?.[1] !== undefined && assignment[2] !== undefined) {
        const called = /^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\(/u.exec(assignment[2])?.[1] ?? "";
        assignments.push({
          name: assignment[1],
          expression: assignment[2],
          line: lineNumber,
          sanitizer: sanitizerPattern.test(called),
        });
      }
      const callPattern = /([A-Za-z_][A-Za-z0-9_.]*)\s*\(([^()]*)\)/gu;
      for (const call of bodyLine.matchAll(callPattern)) {
        const callee = call[1];
        if (callee === undefined) continue;
        const model = {
          callee,
          target: callee.split(".").at(-1) ?? callee,
          args: splitArguments(call[2] ?? ""),
          line: lineNumber,
        };
        calls.push({
          ...model,
          sink: sinkFor(callee),
          parameterizedSql: isParameterizedSql(model),
        });
      }
    }
    const routeDecorator = decorators.find((decorator) =>
      /@[^\s.]+\.(?:get|post|put|patch|delete|route)\s*\(/u.test(decorator.text),
    );
    const routeMatch = routeDecorator === undefined
      ? null
      : /\.([a-z]+)\s*\(\s*["']([^"']+)["']/u.exec(routeDecorator.text);
    let entryPoint: string | undefined;
    if (routeMatch?.[1] !== undefined && routeMatch[2] !== undefined) {
      const decoratorMethod = routeMatch[1].toLocaleLowerCase("en-US");
      const flaskMethod = /methods\s*=\s*\[\s*["']([A-Za-z]+)["']/u.exec(
        routeDecorator?.text ?? "",
      )?.[1];
      const method = decoratorMethod === "route" ? (flaskMethod ?? "GET") : decoratorMethod;
      entryPoint = `${method.toLocaleUpperCase("en-US")} ${routeMatch[2]}`;
    }
    functions.push({
      id: `${path}:${String(index + 1)}:${name}`,
      name,
      file: path,
      line: index + 1,
      params,
      calls,
      assignments,
      ...(entryPoint === undefined ? {} : { entryPoint }),
      ...(routeDecorator === undefined ? {} : { entryLine: routeDecorator.line }),
      entrySourceParams: entryPoint === undefined ? [] : params,
      authBarrier: decorators.some((decorator) => /auth|login|required|permission/iu.test(decorator.text)),
      imports,
    });
    decorators = [];
    index = end - 1;
  }
  return functions;
}

function sinkKey(model: FunctionModel, call: CallModel): string {
  return `${model.file}:${String(call.line)}:${call.callee}`;
}

function buildFinding(
  sink: SinkKind,
  call: CallModel,
  state: TraversalState,
): AttackPathFinding {
  const complete = state.sourceIdentified;
  const crossFunction = state.depth > 0;
  let score = 10;
  if (complete) {
    score += 20;
    score += 20;
    if (crossFunction) score += 15;
    if (state.model.entryPoint !== undefined || state.path.some((node) => node.role === "entry")) score += 15;
    if (!state.sanitizerObserved) score += 10;
    if (!state.authBarrierObserved) score += 10;
  }
  const entryPoint = state.path.find((node) => node.role === "entry")?.symbol;
  return {
    category: sink.category,
    cwe: sink.cwe,
    severity: sink.severity,
    score,
    level: classifyExploitabilityLevel(score),
    ...(entryPoint === undefined ? {} : { entryPoint }),
    attackerSourceIdentified: complete,
    completeDataflowObserved: complete,
    sanitizerObserved: state.sanitizerObserved,
    authBarrierObserved: state.authBarrierObserved,
    runtimeVerified: false,
    activeTestingPerformed: false,
    deploymentConfirmed: false,
    path: [
      ...state.path,
      { file: state.model.file, line: call.line, role: "sink", symbol: sink.symbol, edge: "call" },
    ],
  };
}

function initialState(model: FunctionModel): TraversalState {
  const path: AttackPathNode[] = [];
  if (model.entryPoint !== undefined) {
    path.push({
      file: model.file,
      line: model.entryLine ?? model.line,
      role: "entry",
      symbol: model.entryPoint,
      edge: "route",
    });
  }
  const tainted = new Set(model.entrySourceParams);
  if (model.entrySourceParams[0] !== undefined) {
    path.push({
      file: model.file,
      line: model.line,
      role: "source",
      symbol: model.entrySourceParams[0],
      edge: "argument",
    });
  }
  return {
    model,
    tainted,
    path,
    sourceIdentified: model.entrySourceParams.length > 0,
    sanitizerObserved: false,
    authBarrierObserved: model.authBarrier,
    depth: 0,
  };
}

function moduleStem(path: string): string {
  const normalized = path.replaceAll("\\", "/").replace(/\.(?:jsx?|tsx?|py)$/u, "");
  return normalized.endsWith("/index") ? normalized.slice(0, -"/index".length) : normalized;
}

function resolveImportedFile(callerFile: string, source: string, candidateFile: string): boolean {
  const candidate = moduleStem(candidateFile);
  const callerDirectory = pathPosix.dirname(callerFile.replaceAll("\\", "/"));
  if (source.startsWith(".")) {
    return candidate === pathPosix.normalize(pathPosix.join(callerDirectory, source));
  }
  const pythonSource = source.replaceAll(".", "/");
  return candidate === pythonSource || candidate === pathPosix.join(callerDirectory, pythonSource);
}

function resolveTarget(
  caller: FunctionModel,
  targetName: string,
  models: readonly FunctionModel[],
): FunctionModel | undefined {
  const local = models.filter((model) => model.file === caller.file && model.name === targetName);
  if (local.length === 1) return local[0];
  const imported = caller.imports.get(targetName);
  if (imported === undefined) return undefined;
  const matches = models.filter(
    (model) =>
      model.name === imported.importedName &&
      resolveImportedFile(caller.file, imported.source, model.file),
  );
  return matches.length === 1 ? matches[0] : undefined;
}

export class PassiveExploitabilityAnalyzer {
  readonly #budgets: DataflowBudgets;

  constructor(budgets: DataflowBudgets = defaultBudgets) {
    for (const value of Object.values(budgets)) {
      if (!Number.isFinite(value) || value <= 0) throw new Error("Data-flow budgets must be positive");
    }
    this.#budgets = budgets;
  }

  analyze(files: readonly SourceFileInput[]): PassiveAnalysisResult {
    const startedAt = performance.now();
    const nodeCounter = { value: 0 };
    const reasons: string[] = [];
    const models: FunctionModel[] = [];
    const selectedFiles = files.slice(0, this.#budgets.maxFiles);
    if (files.length > selectedFiles.length) reasons.push("file_limit");

    for (const file of selectedFiles) {
      if (performance.now() - startedAt >= this.#budgets.timeoutMs) {
        reasons.push("timeout");
        break;
      }
      const lower = file.path.toLocaleLowerCase("en-US");
      const text = new TextDecoder("utf-8", { fatal: false }).decode(file.bytes);
      if (/\.(?:js|jsx|ts|tsx)$/u.test(lower)) {
        models.push(...parseTypeScript(file.path, text, nodeCounter, this.#budgets.maxGraphNodes));
      } else if (lower.endsWith(".py")) {
        models.push(...parsePython(file.path, text, nodeCounter, this.#budgets.maxGraphNodes));
      }
      if (nodeCounter.value >= this.#budgets.maxGraphNodes) {
        reasons.push("graph_node_limit");
        break;
      }
    }

    const queue = models.filter((model) => model.entryPoint !== undefined).map(initialState);
    const findings: AttackPathFinding[] = [];
    const surfacedSinks = new Set<string>();
    const visited = new Set<string>();

    while (queue.length > 0) {
      if (performance.now() - startedAt >= this.#budgets.timeoutMs) {
        reasons.push("timeout");
        break;
      }
      const state = queue.shift();
      if (state === undefined) break;
      const visitKey = `${state.model.id}:${[...state.tainted].sort().join(",")}:${String(state.depth)}`;
      if (visited.has(visitKey)) continue;
      visited.add(visitKey);

      const tainted = new Set(state.tainted);
      let sanitizerObserved = state.sanitizerObserved;
      let sourceIdentified = state.sourceIdentified;
      const path = [...state.path];
      let changed = true;
      while (changed) {
        changed = false;
        for (const assignment of state.model.assignments) {
          if (tainted.has(assignment.name) || !isTaintedExpression(assignment.expression, tainted)) continue;
          tainted.add(assignment.name);
          changed = true;
          const directSource = sourceSymbol(assignment.expression);
          if (directSource !== null && !sourceIdentified) {
            sourceIdentified = true;
            path.push({
              file: state.model.file,
              line: assignment.line,
              role: "source",
              symbol: directSource,
              edge: "assignment",
            });
          }
          if (assignment.sanitizer) sanitizerObserved = true;
        }
      }

      for (const call of state.model.calls) {
        const taintedIndexes = call.args.flatMap((argument, index) =>
          isTaintedExpression(argument, tainted) ? [index] : [],
        );
        if (taintedIndexes.length === 0) continue;
        const directSource = call.args.map(sourceSymbol).find((value) => value !== null) ?? null;
        let callPath = path;
        let callSource = sourceIdentified;
        if (directSource !== null && !callSource) {
          callSource = true;
          callPath = [
            ...path,
            {
              file: state.model.file,
              line: call.line,
              role: "source",
              symbol: directSource,
              edge: "argument",
            },
          ];
        }
        if (call.sink !== null) {
          surfacedSinks.add(sinkKey(state.model, call));
          if (!call.parameterizedSql) {
            findings.push(
              buildFinding(call.sink, call, {
                ...state,
                tainted,
                path: callPath,
                sourceIdentified: callSource,
                sanitizerObserved,
              }),
            );
          }
          continue;
        }
        const target = resolveTarget(state.model, call.target, models);
        if (target === undefined || state.depth >= this.#budgets.maxDepth) {
          if (target !== undefined && !reasons.includes("graph_depth_limit")) reasons.push("graph_depth_limit");
          continue;
        }
        const nextTainted = new Set<string>();
        for (const index of taintedIndexes) {
          const parameter = target.params[index];
          if (parameter !== undefined) nextTainted.add(parameter);
        }
        if (nextTainted.size === 0) continue;
        queue.push({
          model: target,
          tainted: nextTainted,
          path: [
            ...callPath,
            { file: target.file, line: target.line, role: "flow", symbol: target.name, edge: "call" },
          ],
          sourceIdentified: callSource,
          sanitizerObserved,
          authBarrierObserved: state.authBarrierObserved || target.authBarrier,
          depth: state.depth + 1,
        });
      }
    }

    for (const model of models) {
      for (const call of model.calls) {
        if (
          call.sink === null ||
          call.parameterizedSql ||
          surfacedSinks.has(sinkKey(model, call))
        ) {
          continue;
        }
        findings.push(
          buildFinding(call.sink, call, {
            model,
            tainted: new Set(),
            path: [],
            sourceIdentified: false,
            sanitizerObserved: false,
            authBarrierObserved: false,
            depth: 0,
          }),
        );
      }
    }

    return {
      findings,
      diagnostics: {
        filesParsed: selectedFiles.length,
        graphNodes: nodeCounter.value,
        partial: reasons.length > 0,
        reasons,
      },
    };
  }
}
