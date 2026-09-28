import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const requiredFiles = [
  "README.md",
  ".gitignore",
  "package.json",
  "pnpm-workspace.yaml",
  "config/tools.json",
  "scripts/bootstrap.mjs",
  "scripts/python-setup.mjs",
  "python/requirements.txt",
  "docs/README.md",
  "docs/tags.md",
  "out/client/gg_client.py",
  "tools/README.md",
  "apk/README.md",
  "reflutter_work/README.md",
];
const expectedDirs = ["docs/analysis", "docs/api", "docs/crypto", "out/client", "out/demo", "tools", "packages"];
const missingFiles = requiredFiles.filter((item) => !fs.existsSync(path.join(ROOT, item)));
const missingDirs = expectedDirs.filter((item) => !fs.existsSync(path.join(ROOT, item)));

if (missingFiles.length || missingDirs.length) {
  if (missingFiles.length) console.error(`缺少文件:\n- ${missingFiles.join("\n- ")}`);
  if (missingDirs.length) console.error(`缺少目录:\n- ${missingDirs.join("\n- ")}`);
  process.exit(1);
}

const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
const tools = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "tools.json"), "utf8"));
if (!packageJson.scripts?.postinstall || !packageJson.scripts?.["tools:install:all"]) {
  console.error("package.json 未配置 postinstall 或 tools:install:all");
  process.exit(1);
}
if (!tools.sets?.core?.length || !tools.tools?.apktool || !tools.tools?.jadx) {
  console.error("config/tools.json 的 core 工具集配置不完整");
  process.exit(1);
}

console.log(`结构校验通过：${requiredFiles.length} 个必需文件、${expectedDirs.length} 个必需目录。`);
console.log(`工具集：core=${tools.sets.core.length} 项，all=${tools.sets.all.length} 项。`);
