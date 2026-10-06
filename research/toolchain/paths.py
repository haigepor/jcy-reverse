# -*- coding: utf-8 -*-
"""paths.py — 研究区统一路径解析。

目录约定（相对本文件）::

    research/
    ├── artifacts/      必需二进制产物 (libcore.so / 设备内存镜像 / 区域 dump)
    ├── toolchain/      分析脚本与本模块
    └── deliverables/   对外交付脚本 (authgen 等)

所有脚本一律通过本模块取路径，禁止再写死 ``out/v11/...`` 之类相对路径。
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))          # research/toolchain
RESEARCH = os.path.dirname(HERE)                            # research
ARTIFACTS = os.path.join(RESEARCH, "artifacts")
DELIVERABLES = os.path.join(RESEARCH, "deliverables")
CAPTURES = os.path.join(RESEARCH, "captures")
CORPUS = os.path.join(RESEARCH, "corpus")
REPORTS = os.path.join(RESEARCH, "reports")
ARCHIVE = os.path.join(RESEARCH, "archive")

# 必需二进制产物
SO = os.path.join(ARTIFACTS, "libcore.so")
IMG = os.path.join(ARTIFACTS, "libcore_dev_img.bin")
IMG_JSON = os.path.join(ARTIFACTS, "libcore_dev_img.json")
REGIONS_JSON = os.path.join(ARTIFACTS, "regions.json")
REGIONS_DIR = os.path.join(ARTIFACTS, "regions")
REGIONS_ALL_JSON = os.path.join(ARTIFACTS, "regions_all.json")
REGIONS_ALL_DIR = os.path.join(ARTIFACTS, "regions_all")
# 最小区域集：由 toolchain/probe_regions.py 统计管线实际读取的区域得出（5 个 / 28.6 MB）
REGIONS_MIN_JSON = os.path.join(ARTIFACTS, "regions_min.json")
REGIONS_MIN_DIR = os.path.join(ARTIFACTS, "regions_min")
MAPS_TXT = os.path.join(ARTIFACTS, "maps.txt")
MAPS2_TXT = os.path.join(ARTIFACTS, "maps2.txt")
BLUTTER_OUT = os.path.join(ARTIFACTS, "blutter_out")

# 数据
PROXY_CAPTURE = os.path.join(CAPTURES, "proxy_capture.jsonl")
PROXY_BODIES = os.path.join(CAPTURES, "proxy_bodies.jsonl")
O_CORPUS = os.path.join(CORPUS, "O_corpus.json")
O_TRUE_CORPUS = os.path.join(CORPUS, "O_true_corpus.json")
VERIFICATION = os.path.join(REPORTS, "VERIFICATION.txt")


def require(*paths):
    """确保给定路径存在，否则抛出可读错误。"""
    for p in paths:
        if not os.path.exists(p):
            raise FileNotFoundError(
                "缺少必需产物: %s\n"
                "请确认 research/artifacts/ 完整（可由 README 中的重建步骤恢复）。" % p)
