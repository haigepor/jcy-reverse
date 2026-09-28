/**
 * Python 环境发现（供 python-setup.mjs / run-tests.mjs 共用）。
 *
 * 探测顺序：PYTHON 环境变量 -> 受管解释器 -> py -3 / python3 / python。
 * 返回 { command, prefix } 或 null。
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const MANAGED_VERSIONS = ["3.13.12", "3.13.14", "3.13.13", "3.12.8"];

export function managedPythonCandidates() {
  const exe = process.platform === "win32" ? "python.exe" : "bin/python";
  return MANAGED_VERSIONS.map((version) =>
    path.join(os.homedir(), ".workbuddy-ai", "binaries", "python", "versions", version, exe),
  );
}

export function runPython(command, args, options = {}) {
  return spawnSync(command, args, {
    encoding: "utf8",
    stdio: "pipe",
    windowsHide: true,
    env: process.env,
    ...options,
  });
}

export function findPython() {
  const candidates = process.env.PYTHON
    ? [[process.env.PYTHON, []]]
    : process.platform === "win32"
      ? [...managedPythonCandidates().map((c) => [c, []]), ["py", ["-3"]], ["python", []]]
      : [...managedPythonCandidates().map((c) => [c, []]), ["python3", []], ["python", []]];

  for (const [command, prefix] of candidates) {
    if (path.isAbsolute(command) && !fs.existsSync(command)) continue;
    const result = runPython(command, [...prefix, "--version"]);
    if (result.status === 0) return { command, prefix };
  }
  return null;
}

/** 项目内虚拟环境的解释器路径。 */
export function venvPythonPath(root) {
  const venvDir = path.join(root, ".venv");
  const relative = process.platform === "win32" ? ["Scripts", "python.exe"] : ["bin", "python"];
  return { venvDir, pythonPath: path.join(venvDir, ...relative) };
}

/**
 * 解析用于执行项目代码的解释器：优先 .venv，其次系统/受管 Python。
 * 返回 { command, prefix, source } 或 null。
 */
export function resolveRuntimePython(root) {
  const { pythonPath } = venvPythonPath(root);
  if (fs.existsSync(pythonPath)) return { command: pythonPath, prefix: [], source: "venv" };
  const found = findPython();
  if (!found) return null;
  return { ...found, source: "system" };
}
