import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { findPython, runPython, venvPythonPath } from "./lib/python-env.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bestEffort = process.argv.includes("--best-effort") || process.env.JCY_BEST_EFFORT === "1";
const withAnalysis = process.argv.includes("--analysis");

const requirementFiles = [
  path.join(ROOT, "python", "requirements.txt"),
  ...(withAnalysis ? [path.join(ROOT, "python", "requirements-analysis.txt")] : []),
];

function warn(message) {
  process.stderr.write(`[jcy-python] WARN ${message}\n`);
}

function fail(message) {
  if (bestEffort) {
    warn(message);
    process.exit(0);
  }
  warn(message);
  process.exit(1);
}

if (process.env.JCY_SKIP_PYTHON === "1") {
  process.stdout.write("[jcy-python] 已通过 JCY_SKIP_PYTHON=1 跳过 Python 环境安装。\n");
  process.exit(0);
}

const { venvDir, pythonPath: venvPython } = venvPythonPath(ROOT);

if (!fs.existsSync(venvPython)) {
  const base = findPython();
  if (!base) {
    fail("未找到 Python 3；gg_client.py 运行依赖未安装。可安装 Python 3.10+ 后执行 pnpm python:install。");
  }
  process.stdout.write(`[jcy-python] 创建虚拟环境: ${path.relative(ROOT, venvDir)}\n`);
  const created = runPython(base.command, [...base.prefix, "-m", "venv", venvDir]);
  if (created.status !== 0) {
    fail(`创建虚拟环境失败: ${created.stderr || created.stdout}`);
  }
}

process.stdout.write(`[jcy-python] 安装依赖: ${requirementFiles.map((f) => path.basename(f)).join(", ")} ...\n`);
const install = runPython(venvPython, [
  "-m", "pip", "install", "--disable-pip-version-check", "-q",
  ...requirementFiles.flatMap((file) => ["-r", file]),
]);
if (install.status !== 0) {
  fail(`Python 依赖安装失败: ${install.stderr || install.stdout}`);
}
process.stdout.write(`[jcy-python] 完成。解释器: ${path.relative(ROOT, venvPython)}\n`);
