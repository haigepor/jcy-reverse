import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONFIG_PATH = path.join(ROOT, "config", "tools.json");
const config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
const toolsRoot = path.join(ROOT, config.toolsDir);
const args = process.argv.slice(2);
const getArg = (name, fallback) => {
  const prefix = `${name}=`;
  const item = args.find((value) => value.startsWith(prefix));
  return item ? item.slice(prefix.length) : fallback;
};
const setName = getArg("--set", "core");
const bestEffort = args.includes("--best-effort") || process.env.JCY_BEST_EFFORT === "1";
const statusOnly = args.includes("--status");
const proxy = process.env.JCY_HTTP_PROXY || process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy || process.env.ALL_PROXY || process.env.all_proxy;
const curl = process.platform === "win32" ? "curl.exe" : "curl";
const skipTools = process.env.JCY_SKIP_TOOLS === "1";
if (skipTools && !args.includes("--status")) {
  log("已通过 JCY_SKIP_TOOLS=1 跳过工具安装。");
  process.exit(0);
}
const failures = [];

function log(message) {
  process.stdout.write(`[jcy-tools] ${message}\n`);
}

function warn(message) {
  process.stderr.write(`[jcy-tools] WARN ${message}\n`);
}

function toolPath(relativePath) {
  return path.join(toolsRoot, relativePath);
}

function existsAndNonEmpty(target) {
  if (!fs.existsSync(target)) return false;
  const stat = fs.statSync(target);
  if (stat.isFile()) return stat.size > 0;
  return fs.readdirSync(target).length > 0;
}

function toolCandidates(tool) {
  return [tool.target || tool.targetDir, ...(tool.aliases || [])].filter(Boolean).map(toolPath);
}

function installedToolPath(tool) {
  return toolCandidates(tool).find(existsAndNonEmpty);
}

function run(command, commandArgs, options = {}) {
  return spawnSync(command, commandArgs, {
    cwd: ROOT,
    encoding: "utf8",
    stdio: options.stdio || "pipe",
    windowsHide: true,
    env: process.env,
  });
}

function curlBaseArgs() {
  const result = ["--fail", "--silent", "--show-error", "--location", "--retry", "2", "--connect-timeout", "30"];
  if (proxy) result.push("--proxy", proxy);
  return result;
}

function curlJson(url) {
  const result = run(curl, [...curlBaseArgs(), "--header", "Accept: application/vnd.github+json", "--header", "User-Agent: jcy-reverse-bootstrap", url]);
  if (result.status !== 0) {
    throw new Error(`请求失败: ${url}\n${result.stderr || result.error?.message || "unknown curl error"}`);
  }
  return JSON.parse(result.stdout);
}

function download(url, destination) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  if (existsAndNonEmpty(destination)) {
    log(`已存在，跳过下载: ${path.relative(ROOT, destination)}`);
    return;
  }
  log(`下载: ${url}`);
  const result = run(curl, [...curlBaseArgs(), "--output", destination, url], { stdio: "pipe" });
  if (result.status !== 0) {
    try { fs.rmSync(destination, { force: true }); } catch {}
    throw new Error(`下载失败: ${url}\n${result.stderr || result.error?.message || "unknown curl error"}`);
  }
}

function releaseAsset(tool) {
  const release = curlJson(`https://api.github.com/repos/${tool.repo}/releases/latest`);
  const pattern = new RegExp(tool.assetPattern);
  const asset = (release.assets || []).find((item) => pattern.test(item.name));
  if (!asset) {
    const names = (release.assets || []).map((item) => item.name).join(", ");
    throw new Error(`未找到匹配资产 ${tool.assetPattern}；可用资产: ${names}`);
  }
  return { url: asset.browser_download_url, name: asset.name, release: release.tag_name };
}

function powershellQuote(value) {
  return `'${value.replaceAll("'", "''")}'`;
}

function extractArchive(archive, destination, archiveType) {
  fs.mkdirSync(destination, { recursive: true });
  if (process.platform === "win32") {
    if (archiveType !== "zip") throw new Error(`Windows 当前仅支持 zip 解压: ${archive}`);
    const command = `$ErrorActionPreference='Stop'; Expand-Archive -LiteralPath ${powershellQuote(archive)} -DestinationPath ${powershellQuote(destination)} -Force`;
    const result = run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", command]);
    if (result.status !== 0) throw new Error(`Expand-Archive 失败: ${result.stderr || result.stdout}`);
    return;
  }
  const result = archiveType === "zip"
    ? run("unzip", ["-q", archive, "-d", destination])
    : run("tar", ["-xf", archive, "-C", destination]);
  if (result.status !== 0) throw new Error(`解压失败: ${result.stderr || result.stdout}`);
}

function moveExtractedRoot(tempDir, targetDir) {
  const entries = fs.readdirSync(tempDir, { withFileTypes: true });
  if (entries.length === 1 && entries[0].isDirectory()) {
    fs.renameSync(path.join(tempDir, entries[0].name), targetDir);
  } else {
    fs.renameSync(tempDir, targetDir);
  }
}

function installArchive(tool, url) {
  const targetDir = toolPath(tool.targetDir);
  if (installedToolPath(tool)) {
    log(`已存在，跳过安装: ${path.relative(ROOT, installedToolPath(tool))}`);
    return;
  }
  const tempBase = fs.mkdtempSync(path.join(ROOT, ".jcy-download-"));
  const archive = path.join(tempBase, tool.archiveType === "zip" ? "tool.zip" : "tool.tar.gz");
  const extracted = path.join(tempBase, "extracted");
  try {
    download(url, archive);
    extractArchive(archive, extracted, tool.archiveType);
    fs.mkdirSync(path.dirname(targetDir), { recursive: true });
    moveExtractedRoot(extracted, targetDir);
    log(`安装完成: ${path.relative(ROOT, targetDir)}`);
  } finally {
    fs.rmSync(tempBase, { recursive: true, force: true });
  }
}

function installGit(tool) {
  const targetDir = toolPath(tool.targetDir);
  if (installedToolPath(tool)) {
    log(`已存在，跳过克隆: ${path.relative(ROOT, installedToolPath(tool))}`);
    return;
  }
  fs.mkdirSync(path.dirname(targetDir), { recursive: true });
  log(`克隆: ${tool.url}`);
  const result = run("git", ["clone", "--depth", "1", tool.url, targetDir], { stdio: "pipe" });
  if (result.status !== 0) throw new Error(`git clone 失败: ${result.stderr || result.stdout}`);
}

function installTool(name) {
  const tool = config.tools[name];
  if (!tool) throw new Error(`配置中不存在工具: ${name}`);
  if (tool.kind === "github-release") {
    const existing = installedToolPath(tool);
    if (existing) {
      log(`已存在，跳过安装: ${path.relative(ROOT, existing)}`);
      return;
    }
    const asset = releaseAsset(tool);
    const destination = toolPath(tool.target);
    log(`${name}: latest ${asset.release} -> ${asset.name}`);
    download(asset.url, destination);
  } else if (tool.kind === "archive") {
    const url = tool.urls?.[process.platform];
    if (!url) throw new Error(`${name} 没有当前平台 ${process.platform} 的下载地址`);
    installArchive(tool, url);
  } else if (tool.kind === "git") {
    installGit(tool);
  } else {
    throw new Error(`${name} 使用了未知安装类型: ${tool.kind}`);
  }
}

function showStatus() {
  const names = [...new Set(Object.values(config.sets).flat())];
  for (const name of names) {
    const tool = config.tools[name];
    const target = installedToolPath(tool) || toolPath(tool.target || tool.targetDir);
    const state = installedToolPath(tool) ? "installed" : "missing";
    process.stdout.write(`${state.padEnd(10)} ${name.padEnd(18)} ${path.relative(ROOT, target)}\n`);
  }
}

if (statusOnly) {
  showStatus();
  process.exit(0);
}

const selected = config.sets[setName];
if (!selected) {
  warn(`未知工具集 ${setName}。可用集合: ${Object.keys(config.sets).join(", ")}`);
  process.exit(2);
}

fs.mkdirSync(toolsRoot, { recursive: true });
log(`安装集合: ${setName}（${selected.length} 项）`);
for (const name of selected) {
  try {
    installTool(name);
  } catch (error) {
    failures.push({ name, message: error.message });
    warn(`${name}: ${error.message}`);
    if (!bestEffort) break;
  }
}

if (failures.length > 0) {
  warn(`完成但有 ${failures.length} 项失败。网络恢复后可重复执行 pnpm tools:install 或 pnpm tools:install:all。`);
  if (!bestEffort) process.exit(1);
} else {
  log("工具安装完成。");
}
