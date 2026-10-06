/**
 * 运行 Python 侧测试。
 *
 * 依次执行：
 *   1. tests/test_channels.py    — 三通道加解密向量回归
 *   2. tests/test_auth_pure.py   — authentication 算法纯逻辑单元测试（无需模拟器）
 *   3. tests/test_authgen.py     — authentication 端到端回归（需要 research/artifacts/，缺失时 SKIP=77）
 *
 * 优先使用项目 .venv；若未创建则回退系统 Python，并在缺少依赖时给出明确提示。
 */
import path from "node:path";
import { fileURLToPath } from "node:url";

import { resolveRuntimePython, runPython } from "./lib/python-env.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TESTS = [
  ["三通道向量", "test_channels.py"],
  ["auth 纯逻辑", "test_auth_pure.py"],
  ["auth 端到端", "test_authgen.py"],
];

const runtime = resolveRuntimePython(ROOT);
if (!runtime) {
  process.stderr.write("[jcy-test] 未找到可用的 Python 3，请先执行 pnpm python:install。\n");
  process.exit(1);
}

process.stdout.write(`[jcy-test] 解释器(${runtime.source}): ${runtime.command}\n`);

let failed = 0;
for (const [label, file] of TESTS) {
  const testFile = path.join(ROOT, "tests", file);
  process.stdout.write(`\n[jcy-test] === ${label} (${file}) ===\n`);
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

  const status = result.status ?? 1;
  if (status === 77) {
    process.stdout.write(`[jcy-test] ${file} SKIP（依赖缺失：research/artifacts/ 未重建）\n`);
    continue;
  }
  if (status !== 0) {
    if ((result.stderr || "").includes("Crypto")) {
      process.stderr.write("[jcy-test] 缺少 pycryptodome，请执行 pnpm python:install。\n");
    }
    failed += 1;
  }
}

if (failed) {
  process.stderr.write(`\n[jcy-test] 失败 ${failed} 个测试文件\n`);
  process.exit(1);
}
process.stdout.write("\n[jcy-test] 全部通过\n");
