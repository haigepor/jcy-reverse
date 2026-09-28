import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const venvDir = path.join(ROOT, ".venv");
const requirements = path.join(ROOT, "python", "requirements.txt");
const bestEffort = process.argv.includes("--best-effort") || process.env.JCY_BEST_EFFORT === "1";

function run(command, args) {
  return spawnSync(command, args, { cwd: ROOT, encoding: "utf8", stdio: "pipe", windowsHide: true, env: process.env });
}

function warn(message) {
  process.stderr.write(`[jcy-python] WARN ${message}\n`);
}

if (process.env.JCY_SKIP_PYTHON === "1") {
  process.stdout.write("[jcy-python] 已通过 JCY_SKIP_PYTHON=1 跳过 Python 环境安装。\n");
  process.exit(0);
}

const candidates = process.env.PYTHON
  ? [[process.env.PYTHON, []]]
  : process.platform === "win32"
    ? [["py", ["-3"]], ["python", []]]
    : [["python3", []], ["python", []]];

let pythonCommand;
let pythonPrefix;
for (const [command, prefix] of candidates) {
  const result = run(command, [...prefix, "--version"]);
  if (result.status === 0) {
    pythonCommand = command;
    pythonPrefix = prefix;
    break;
  }
}

if (!pythonCommand) {
  const message = "未找到 Python 3；gg_client.py 运行依赖未安装。可安装 Python 3.10+ 后执行 pnpm python:install。";
  if (bestEffort) { warn(message); process.exit(0); }
  warn(message); process.exit(1);
}

const venvPython = process.platform === "win32"
  ? path.join(venvDir, "Scripts", "python.exe")
  : path.join(venvDir, "bin", "python");

if (!fs.existsSync(venvPython)) {
  process.stdout.write(`[jcy-python] 创建虚拟环境: ${path.relative(ROOT, venvDir)}\n`);
  const result = run(pythonCommand, [...pythonPrefix, "-m", "venv", venvDir]);
  if (result.status !== 0) {
    const message = `创建虚拟环境失败: ${result.stderr || result.stdout}`;
    if (bestEffort) { warn(message); process.exit(0); }
    warn(message); process.exit(1);
  }
}

process.stdout.write("[jcy-python] 安装 requests / pycryptodome ...\n");
const install = run(venvPython, ["-m", "pip", "install", "--disable-pip-version-check", "-r", requirements]);
if (install.status !== 0) {
  const message = `Python 依赖安装失败: ${install.stderr || install.stdout}`;
  if (bestEffort) { warn(message); process.exit(0); }
  warn(message); process.exit(1);
}
process.stdout.write(`[jcy-python] 完成。解释器: ${path.relative(ROOT, venvPython)}\n`);
