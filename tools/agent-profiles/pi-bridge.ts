// GitVault checker bridge: exposes a checker's Python tools to a Pi session.
//
// The Python plugin owns every judgement -- schemas, path safety, the verdict
// contract. This file is only the pipe: the checker lists its tools in
// GITVAULT_TOOLS, the bridge registers them with Pi and forwards each call to
// the plugin's `--serve-tools` process, one JSON request per stdin line, one
// JSON reply per stdout line. Review state (pages read, sources fetched) lives
// in that process for the run's lifetime, so a subprocess per call cannot
// silently reset it.

import { spawn, type ChildProcess } from "node:child_process";
import { createInterface, type Interface } from "node:readline";
import { join } from "node:path";

interface ToolSpec {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export default function (pi: any) {
  const pluginDir = process.env.GITVAULT_CHECKER_DIR;
  const runDir = process.env.GITVAULT_RUN_DIR;
  let specs: ToolSpec[] = [];
  try {
    specs = JSON.parse(process.env.GITVAULT_TOOLS || "[]");
  } catch {
    specs = [];
  }
  if (!pluginDir || !runDir || specs.length === 0) return;

  let child: ChildProcess | null = null;
  let lines: Interface | null = null;
  let seq = 0;
  const pending = new Map<number, (line: string) => void>();

  // One python process for the whole review: the plugin's in-memory state
  // (diff pagination, fetched sources) is part of the verdict contract.
  function tools(): ChildProcess {
    if (child) return child;
    child = spawn(process.env.GITVAULT_PYTHON || "python3", ["-I", join(pluginDir, "__init__.py"), "--serve-tools", "--run", runDir], {
      stdio: ["pipe", "pipe", "inherit"],
    });
    lines = createInterface({ input: child.stdout });
    lines.on("line", (line) => {
      let reply: { id?: number };
      try {
        reply = JSON.parse(line);
      } catch {
        return;
      }
      const resolve = pending.get(Number(reply.id));
      if (resolve) {
        pending.delete(Number(reply.id));
        resolve(line);
      }
    });
    child.on("exit", () => {
      child = null;
      for (const resolve of pending.values()) resolve(JSON.stringify({ error: "tool host exited" }));
      pending.clear();
    });
    return child;
  }

  for (const spec of specs) {
    pi.registerTool({
      name: spec.name,
      label: spec.name,
      description: spec.description,
      parameters: spec.parameters,
      async execute(_id: string, args: unknown) {
        const id = ++seq;
        const reply = await new Promise<string>((resolve) => {
          pending.set(id, resolve);
          tools().stdin?.write(JSON.stringify({ id, tool: spec.name, args: args ?? {} }) + "\n");
        });
        let parsed: { result?: unknown; error?: string };
        try {
          parsed = JSON.parse(reply);
        } catch {
          parsed = { error: "unreadable tool reply" };
        }
        const text = typeof parsed.result === "string" ? parsed.result : JSON.stringify(parsed.result ?? { error: parsed.error || "tool failed" });
        return { content: [{ type: "text", text }] };
      },
    });
  }

  pi.on("session_shutdown", () => {
    child?.kill();
    child = null;
  });
}
