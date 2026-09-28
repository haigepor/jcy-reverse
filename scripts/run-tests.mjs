/**
 * 运行 Python 侧测试：packages/protocol/tests/test_channels.py
 *
 * 优先使用项目 .venv；若未创建则回退系统 Python，并在缺少 pycryptodome 时给出明确提示。
 */
import path from "node:path";
import { fileURLToPath } from "node:url";

import { resolveRuntimePython, runPython } from "./lib/python-env.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const testFile = path.join(ROOT, "packages", "protocol", "tests", "test_channels.py");

const runtime = resolveRuntimePython(ROOT);
if (!runtime) {
  process.stderr.write("[jcy-test] 未找到可用的 Python 3，请先执行 pnpm python:install。\n");
  process.exit(1);
}

process.stdout.write(`[jcy-test] 解释器(${runtime.source}): ${runtime.command}\n`);

const result = runPython(runtime.command, [...runtime.prefix, testFile]);
process.stdout.write(result.stdout || "");
if (result.stderr) process.stderr.write(result.stderr);

if (result.error) {
  process.stderr.write(
    `[jcy-test] 无法启动 Python 子进程: ${result.error.code || result.error.message}\n` +
      `[jcy-test] 若为 EBUSY/EPERM，说明当前环境限制了子进程创建（部分沙箱会如此）。\n` +
      `[jcy-test] 可改为直接执行: ${runtime.command} ${testFile}\n`,
  );
  process.exit(1);
}

if (result.status !== 0) {
  if ((result.stderr || "").includes("Crypto")) {
    process.stderr.write("[jcy-test] 缺少 pycryptodome，请执行 pnpm python:install。\n");
  }
  process.exit(result.status ?? 1);
}
