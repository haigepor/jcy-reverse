/**
 * 项目骨架校验：文档 ↔ 目录 双向一致性。
 *
 * 校验项：
 *  1. README.md 目录树中的每个条目，在文件系统上真实存在
 *  2. 文件系统顶层条目（排除 .git / node_modules / .venv / .workbuddy-ai），都在 README 目录树中登记
 *  3. docs/_sidebar.md 与各文档中的相对链接指向真实文件
 *  4. 关键文件与目录完整性
 *  5. 工具清单（config/tools.json）与 package.json 脚本一致性
 *
 * 任一失败退出码非 0。
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const IGNORED_TOP_LEVEL = new Set([".git", "node_modules", ".venv", ".workbuddy-ai"]);
const GLOB_CHARS = /[*?[\]{}]/;

const errors = [];
const warnings = [];

function exists(target) {
  return fs.existsSync(path.join(ROOT, target));
}

// ---------------------------------------------------------------------------
// 1 + 2. README 目录树解析与双向比对
// ---------------------------------------------------------------------------

function extractTreeLines() {
  const readme = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
  const blocks = readme.match(/```[^\n]*\n[\s\S]*?```/g) || [];
  for (const block of blocks) {
    const body = block.replace(/^```[^\n]*\n/, "").replace(/```$/, "");
    if (body.includes("├──") || body.includes("└──")) return body.split("\n");
  }
  return null;
}

function parseTree(lines) {
  const entries = [];
  const stack = [];
  for (const line of lines) {
    const match = line.match(/^([│\s]*)[├└]──\s+(.+?)\s*$/);
    if (!match) continue;
    const depth = Math.floor(match[1].length / 4);
    const name = match[2].split(/\s{2,}/)[0].replace(/\/$/, "").trim();
    if (!name) continue;
    stack[depth] = name;
    stack.length = depth + 1;
    entries.push({ depth, name, segments: [...stack] });
  }
  return entries;
}

function checkReadmeTree() {
  const lines = extractTreeLines();
  if (!lines) {
    errors.push("README.md 中未找到目录树代码块");
    return;
  }
  const entries = parseTree(lines);
  if (entries.length === 0) {
    errors.push("README.md 目录树解析结果为空");
    return;
  }

  const declaredTopLevel = new Set();
  for (const entry of entries) {
    if (GLOB_CHARS.test(entry.name)) continue; // 形如 *.py 的说明性条目
    const target = entry.segments.join("/");
    if (entry.depth === 0) declaredTopLevel.add(entry.name);
    if (!exists(target)) errors.push(`README 目录树登记的路径不存在: ${target}`);
  }

  for (const name of fs.readdirSync(ROOT)) {
    if (IGNORED_TOP_LEVEL.has(name)) continue;
    if (!declaredTopLevel.has(name)) errors.push(`文件系统存在但 README 目录树未登记: ${name}`);
  }

  process.stdout.write(`  README 目录树：条目 ${entries.length} 个，顶层 ${declaredTopLevel.size} 项已双向比对\n`);
}

// ---------------------------------------------------------------------------
// 3. Markdown 相对链接校验
// ---------------------------------------------------------------------------

function checkLinksIn(file, baseDir) {
  const text = fs.readFileSync(path.join(ROOT, file), "utf8");
  const links = [...text.matchAll(/\[[^\]]*\]\(([^)\s]+)\)/g)].map((m) => m[1]);
  let checked = 0;
  for (const link of links) {
    if (/^(https?:|mailto:|#)/.test(link)) continue;
    const clean = link.split("#")[0];
    if (!clean || GLOB_CHARS.test(clean)) continue;
    checked += 1;
    if (!fs.existsSync(path.resolve(ROOT, baseDir, clean))) {
      errors.push(`${file} 链接指向不存在的文件: ${link}`);
    }
  }
  return checked;
}

function checkLinks() {
  let total = 0;
  total += checkLinksIn("README.md", ".");
  total += checkLinksIn("docs/_sidebar.md", "docs");
  total += checkLinksIn("docs/README.md", "docs");
  for (const name of fs.readdirSync(path.join(ROOT, "docs"))) {
    const full = path.join(ROOT, "docs", name);
    if (!fs.statSync(full).isDirectory()) continue;
    for (const child of fs.readdirSync(full)) {
      if (child.endsWith(".md")) total += checkLinksIn(`docs/${name}/${child}`, `docs/${name}`);
    }
  }
  process.stdout.write(`  文档内链：校验 ${total} 条\n`);
}

// ---------------------------------------------------------------------------
// 4. 关键文件与目录
// ---------------------------------------------------------------------------

const REQUIRED_FILES = [
  "README.md",
  ".gitignore",
  ".gitattributes",
  ".editorconfig",
  "LICENSE",
  "CHANGELOG.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "package.json",
  "pnpm-workspace.yaml",
  "config/tools.json",
  "scripts/bootstrap.mjs",
  "scripts/python-setup.mjs",
  "scripts/run-tests.mjs",
  "scripts/validate-structure.mjs",
  "scripts/lib/python-env.mjs",
  "python/requirements.txt",
  "python/requirements-analysis.txt",
  "packages/README.md",
  "packages/protocol/README.md",
  "packages/protocol/pyproject.toml",
  "packages/protocol/jcy_protocol/__init__.py",
  "packages/protocol/jcy_protocol/channels.py",
  "packages/protocol/jcy_protocol/vectors.py",
  "packages/protocol/tests/test_channels.py",
  "docs/README.md",
  "docs/_sidebar.md",
  "docs/installation.md",
  "docs/structure.md",
  "docs/scripts-index.md",
  "docs/tags.md",
  "docs/git-push-prompt.md",
  "out/client/gg_client.py",
  "out/README.md",
  "tools/README.md",
  "apk/README.md",
  "reflutter_work/README.md",
];

const REQUIRED_DIRS = [
  "docs/analysis",
  "docs/api",
  "docs/crypto",
  "out/client",
  "out/demo",
  "tools",
  "packages",
  "scripts/lib",
];

function checkRequired() {
  for (const file of REQUIRED_FILES) {
    if (!exists(file)) errors.push(`缺少必需文件: ${file}`);
  }
  for (const dir of REQUIRED_DIRS) {
    if (!exists(dir)) errors.push(`缺少必需目录: ${dir}`);
  }
  process.stdout.write(`  完整性：必需文件 ${REQUIRED_FILES.length} 个、必需目录 ${REQUIRED_DIRS.length} 个\n`);
}

// ---------------------------------------------------------------------------
// 5. 工具清单与脚本
// ---------------------------------------------------------------------------

function checkToolManifest() {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const tools = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "tools.json"), "utf8"));

  for (const script of ["postinstall", "test", "validate", "tools:install", "tools:install:all", "tools:status"]) {
    if (!pkg.scripts?.[script]) errors.push(`package.json 缺少脚本: ${script}`);
  }
  for (const setName of ["core", "all"]) {
    for (const name of tools.sets?.[setName] || []) {
      if (!tools.tools?.[name]) errors.push(`config/tools.json 的 ${setName} 集引用了未定义工具: ${name}`);
    }
  }
  for (const [name, tool] of Object.entries(tools.tools || {})) {
    if (!tool.kind) errors.push(`工具 ${name} 缺少 kind`);
    if (!tool.description) warnings.push(`工具 ${name} 缺少 description`);
  }
  process.stdout.write(`  工具清单：core=${(tools.sets?.core || []).length} 项，all=${(tools.sets?.all || []).length} 项\n`);
}

// ---------------------------------------------------------------------------

process.stdout.write("[jcy-validate] 开始校验\n");
checkReadmeTree();
checkLinks();
checkRequired();
checkToolManifest();

for (const warning of warnings) process.stderr.write(`  WARN  ${warning}\n`);

if (errors.length) {
  process.stderr.write(`\n[jcy-validate] 失败，共 ${errors.length} 项：\n`);
  for (const error of errors) process.stderr.write(`  - ${error}\n`);
  process.exit(1);
}

process.stdout.write("[jcy-validate] 通过：文档与目录结构一致。\n");
