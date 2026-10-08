// web:server —— 启动 FastAPI 桥（src/web/server/main.py，127.0.0.1:8792）。
// 优先用仓库 .venv 的解释器（fastapi/uvicorn 已装），退回系统 python。
// 桥内 Unicorn×libcore.so 模拟存在偶发原生崩溃（输入相关分支，见 docs/frontend.md
// 已知边界），本脚本做监督自愈：异常退出自动拉起（auth 盘缓存让重启后即热）。
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY = path.join(ROOT, "src", "web", "server", "main.py");

const candidates = [
  path.join(ROOT, ".venv", "Scripts", "python.exe"), // Windows
  path.join(ROOT, ".venv", "bin", "python"), // POSIX
  "python",
  "python3",
];

const bin = candidates.find((c) =>
  c.includes(path.sep) ? existsSync(c) : true,
);

const MAX_RAPID = 5; // 连续快速崩溃保护
let rapid = 0;

console.log(`[web:server] ${bin} ${ENTRY}`);

for (;;) {
  const t0 = Date.now();
  const child = spawn(bin, [ENTRY], { stdio: "inherit", cwd: ROOT });
  const code = await new Promise((resolve) => child.on("exit", resolve));
  const uptime = Date.now() - t0;
  if (uptime > 60_000) rapid = 0;
  if (code === 0) {
    console.log("[web:server] 正常退出");
    break;
  }
  rapid += 1;
  if (rapid > MAX_RAPID) {
    console.error(`[web:server] 连续 ${rapid} 次异常退出，停止重启（请检查 research 工具链）`);
    process.exit(1);
  }
  console.error(`[web:server] 进程异常退出 code=${code}（运行 ${(uptime / 1000) | 0}s），3s 后自动重启…`);
  await new Promise((r) => setTimeout(r, 3000));
}

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => process.exit(0));
}
