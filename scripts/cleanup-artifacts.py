#!/usr/bin/env python
"""cleanup-artifacts.py —— 清理 research/ 下的可重建产物。

设计原则（与 README「证据可复现」约定一致）：
  * 只删「可由脚本重建」或「纯中间态」的产物；
  * 一切被 docs/ 或 reports/ 引用为证据的文件一律保留
    （因此保留 tmp_*.py / tmp_*.json / tmp_*.txt / tmp_*.out）；
  * 所有 .dll 一律保留（c_engine.py 的 _DLL_CANDIDATES 回退链会用到）；
  * 源码 / 脚本 / .json 元数据 / .pem / .a 一律保留。

用法：
    python scripts/cleanup-artifacts.py            # 干跑，只列清单
    python scripts/cleanup-artifacts.py --apply    # 实际删除
    python scripts/cleanup-artifacts.py --apply --manifest out.txt
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "research"

# ---------------------------------------------------------------- 删除规则
# 每项： (说明, 基准目录, 模式列表, 是否为目录)
STAGE1: list[tuple[str, Path, list[str], bool]] = [
    # ---- 组 1：临时中间产物（保留 tmp_*.py / .json / .txt / .out 作为证据）----
    ("1a tmp 大二进制/日志/截图", R, [
        "tmp_*.bin", "tmp_*.pkl", "tmp_*.log", "tmp_*.png",
        "tmp_*.so", "tmp_*.exe", "tmp_*.dmp", "tmp_*.trace",
    ], False),
    ("1b tmp 工作目录", R, [
        "tmp_perf", "tmp_regions", "tmp_go_jocy", "tmp_gui_test",
        "tmp_audit_b", "tmp_junzi",
    ], True),
    ("1c 缓存与备份", R, ["__pycache__", "_opt_backup"], True),
    ("1d 未登记工具解压包", R / "tools", ["*"], True),

    # ---- 组 2：reports 巨型转储（gen_ref_trace.py / 重跑可重建）----
    ("2 reports 巨型 trace/日志", R / "reports", [
        "ref_trace_128blk.txt", "reg_c.txt",
        "dec_run.log", "dec_run2.log", "dec_run3.log", "dec_run4.log",
        "trace_py_1blk.txt", "ref_trace_1blk.txt",
    ], False),

    # ---- 组 3：engine_c 构建产物（源码/.dll/.a/.json 保留）----
    ("3a 引擎内存镜像", R / "engine_c", ["image.bin", "image1.bin", "image128.bin", "image639.bin"], False),
    ("3b PC trace 转储", R / "engine_c", ["*.bin.trace"], False),
    ("3c 测试可执行", R / "engine_c", ["*.exe"], False),
    ("3d 编译中间对象", R / "engine_c", ["*.o"], False),
    ("3e 旧版本备份", R / "engine_c", ["*.bak"], False),

    # ---- 组 4：artifacts 冗余 ----
    ("4 artifacts 冗余", R / "artifacts", ["libcore_dev_img.bin", "base_runtime.apk"], False),

    # ---- 组 5：原始内存镜像（不可再生，已获用户明确批准删除）----
    ("5a 内存镜像目录", R / "captures" / "rsa_scan", [
        "memdump", "livedump", "livedump2_pull", "live", "emu_mem",
    ], True),
    ("5b 样本 APK 副本", R / "captures" / "rsa_scan", ["base.apk"], False),
]

# ---------------------------------------------------------------- 第二遍
# 目标：research/ 只留「工具链能跑起来 + 结论可复现」的最小集。
# 删除对象 = 可由 tools/ 里现成工具重跑出来的原始输入 / 反编译产物 / 历史归档。
STAGE2: list[tuple[str, Path, list[str], bool]] = [
    # ---- 组 6：artifacts 里的可重建输入 ----
    ("6a 全量内存区域 dump（备用，probe_regions.py 可重跑）", R / "artifacts", ["regions_all"], True),
    ("6b jadx 反编译产物（tools/jadx 可重跑）", R / "artifacts", ["jadx_out"], True),
    ("6c 设备 pull 的 .so 副本（可重新 pull）", R / "artifacts", ["device_libs"], True),
    ("6d 早期小规模区域集（已被 regions_min 取代）", R / "artifacts", ["regions"], True),
    ("6e blutter 重复产物（blutter_out 已保留）", R / "artifacts", ["blutter_rt", "blutter_rt_in"], True),

    # ---- 组 7：captures 里的内存 dump 与重复反编译 ----
    ("7a blutter 重跑产物（与 artifacts/blutter_out 重复）", R / "captures" / "rsa_scan", ["blutter_now"], True),
    ("7b RSA 追猎期的内存 dump 与临时语料", R / "captures" / "rsa_scan", [
        "pair", "pair2", "watch", "watch_plain", "watch_action",
        "watch_action_in", "livedump2", "livedump.pull",
        "replay", "replay_corpus", "lua", "__pycache__",
    ], True),

    # ---- 组 8：历史归档（docs 只引用 archive/ 与 archive/legacy-scripts/）----
    ("8a v5–v12 历史版本", R / "archive", ["versions"], True),
    ("8b 早期测试产物", R / "archive", ["test-artifacts"], True),
    ("8c 早期零散产物", R / "archive", ["legacy-artifacts"], True),

    # ---- 组 9：engine_c 生成源码变体（gen_engine.py 可重新生成）----
    ("9 引擎生成源码变体", R / "engine_c", [
        "jcy_engine_clean.c", "jcy_engine_dbg.c",
        "jcy_engine_trace.c", "jcy_engine_trace24.c",
        "jcy_fuse.c",
    ], False),

    # ---- 组 10：交付物缓存 ----
    ("10 交付物缓存", R / "deliverables", ["__pycache__"], True),
]

STAGES = {1: STAGE1, 2: STAGE2}
GROUPS = STAGE1  # 向后兼容

# 明确保留（即使被上面的 glob 命中）—— 防御性白名单。
# 注意：只放「源码/脚本/元数据」类后缀，不能放 .txt/.json/.bin ——
# 组 2 要删的巨型 trace 正是 .txt，组 1a 已经用显式扩展名排除了 .py/.json/.txt。
KEEP_SUFFIX = {".py", ".c", ".h", ".cc", ".cpp", ".hpp", ".sh", ".dll", ".a",
               ".pem", ".js", ".ts", ".tsx", ".jsx", ".bat", ".md", ".jsonl"}
KEEP_NAMES = {"jcy_fuse24.dll", "jcy_fuse.dll", "jcy_engine.dll",
              "libgcc_s_seh-1.dll", "libwinpthread-1.dll", "README.md"}


def human(n: int) -> str:
    return f"{n / 1048576:.1f} MB"


def collect(groups: list[tuple[str, Path, list[str], bool]]) -> list[tuple[str, Path, int, bool]]:
    """返回 [(组名, 路径, 字节数, 是否目录)]。"""
    out: list[tuple[str, Path, int, bool]] = []
    seen: set[Path] = set()

    for label, base, patterns, _is_dir in groups:
        if not base.is_dir():
            continue
        for pat in patterns:
            for p in sorted(base.glob(pat)):
                if p in seen:
                    continue
                # 防御性白名单
                if p.name in KEEP_NAMES:
                    continue
                if p.is_file() and p.suffix.lower() in KEEP_SUFFIX:
                    # 组 1a 里 .so/.exe/.bin/.pkl/.log/.png 不是白名单后缀，
                    # 但 .txt/.json 等在白名单里 —— 正好实现"保留证据"。
                    continue
                if p.is_dir():
                    size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
                    if size == 0 and not any(p.rglob("*")):
                        pass  # 空目录也删
                else:
                    size = p.stat().st_size
                seen.add(p)
                out.append((label, p, size, p.is_dir()))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="实际删除（默认干跑）")
    ap.add_argument("--manifest", default=None, help="把清单写到文件")
    ap.add_argument("--stage", type=int, default=1, choices=[1, 2],
                    help="1=临时产物与转储（默认）；2=可重建输入/反编译产物/历史归档")
    ap.add_argument("--prune-empty", action="store_true",
                    help="删除后清掉残留的空目录")
    args = ap.parse_args()

    items = collect(STAGES[args.stage])
    total = sum(s for _, _, s, _ in items)

    by_group: dict[str, list[tuple[Path, int, bool]]] = {}
    for label, p, s, isdir in items:
        by_group.setdefault(label, []).append((p, s, isdir))

    lines: list[str] = []
    lines.append(f"# 清理清单 stage{args.stage}  ({'实际删除' if args.apply else '干跑'})")
    lines.append(f"# 合计 {len(items)} 项 / {human(total)}")
    lines.append("")
    for label, rows in by_group.items():
        gs = sum(s for _, s, _ in rows)
        lines.append(f"## {label}  —— {len(rows)} 项 / {human(gs)}")
        for p, s, isdir in rows:
            rel = p.relative_to(ROOT).as_posix()
            lines.append(f"  {'DIR ' if isdir else 'FILE'} {human(s):>10}  {rel}")
        lines.append("")

    text = "\n".join(lines)
    print(text if len(items) <= 80 else text[:4000] + f"\n...（完整清单见 --manifest，共 {len(items)} 项）")

    if args.manifest:
        Path(args.manifest).write_text(text, encoding="utf-8")
        print(f"[manifest] 已写入 {args.manifest}")

    print(f"\n合计：{len(items)} 项 / {human(total)}")

    if not args.apply:
        print("[干跑] 未做任何改动。加 --apply 执行删除。")
        return 0

    ok = fail = 0
    freed = 0
    for label, p, s, isdir in items:
        try:
            if isdir:
                shutil.rmtree(p)
            else:
                os.remove(p)
            ok += 1
            freed += s
        except Exception as e:  # noqa: BLE001
            fail += 1
            print(f"  FAIL {p}: {e}", file=sys.stderr)

    print(f"[完成] 成功 {ok} 项 / 失败 {fail} 项，释放 {human(freed)}")

    if args.prune_empty:
        removed = 0
        # 自底向上清理空目录（保留 research/ 下已登记的顶层目录）
        for p in sorted(R.rglob("*"), key=lambda x: len(x.parts), reverse=True):
            if p.is_dir() and not any(p.iterdir()):
                try:
                    p.rmdir()
                    removed += 1
                except OSError:
                    pass
        print(f"[prune] 清理空目录 {removed} 个")

    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
