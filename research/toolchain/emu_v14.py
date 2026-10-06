# -*- coding: utf-8 -*-
# emu_v14.py — 加载设备 rw 区域的模拟器（默认用最小集 regions_min，可切回全集 regions_all）
import os, sys, json, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
import paths as _P
from v13 import Emu3, DEV_BASE, IMG_SIZE

ALL_JSON = _P.REGIONS_ALL_JSON
ALL_DIR = _P.REGIONS_ALL_DIR


class Emu4(Emu3):
    """在 Emu3 基础上再灌入设备 rw 区域（只灌不与已映射区重叠的部分）。

    默认使用**最小区域集** `regions_min`（5 个区域 / 28.6 MB，由
    `toolchain/probe_regions.py` 统计得出），可在构造时指定：

        Emu4(regions_json=..., regions_dir=...)          # 自定义
        Emu4(regions_json=_P.REGIONS_ALL_JSON,
             regions_dir=_P.REGIONS_ALL_DIR)             # 全量 813 区域 / 424 MB
    """

    def __init__(self, *a, regions_json=None, regions_dir=None, **kw):
        self.regions_json = regions_json or _P.REGIONS_MIN_JSON
        self.regions_dir = regions_dir or _P.REGIONS_MIN_DIR
        self.all_loaded = 0
        self.all_skipped = 0
        super().__init__(*a, **kw)
        self._load_all()

    def _load_all(self):
        if not os.path.exists(self.regions_json):
            # 最小集缺失时回退到全集
            self.regions_json, self.regions_dir = ALL_JSON, ALL_DIR
            if not os.path.exists(self.regions_json):
                return
        for r in json.load(open(self.regions_json)):
            p = os.path.join(self.regions_dir, r["file"])
            if not os.path.exists(p):
                continue
            data = open(p, "rb").read()
            base = r["base"]
            size = len(data)
            # 若与 DEV 镜像重叠, 跳过重叠部分
            lo, hi = base, base + size
            dlo, dhi = DEV_BASE, DEV_BASE + IMG_SIZE
            if hi <= dlo or lo >= dhi:
                self._map_region(base, data)
                continue
            # 部分重叠: 只写非重叠尾部/头部
            if lo < dlo:
                n = dlo - lo
                self._map_region(lo, data[:n])
            if hi > dhi:
                n = dhi - lo
                self._map_region(dhi, data[n:])

    def _map_region(self, base, data):
        if not data:
            return
        size = (len(data) + 0xFFF) & ~0xFFF
        try:
            self.uc.mem_map(base, size, UC_PROT_ALL)
        except UcError:
            # 已映射 -> 直接写入(可能部分失败)
            try:
                self.uc.mem_write(base, data)
                self.all_loaded += 1
            except UcError:
                self.all_skipped += 1
            return
        self.uc.mem_write(base, data)
        self.all_loaded += 1


if __name__ == "__main__":
    e = Emu4()
    print("loaded regions:", e.all_loaded, "skipped:", e.all_skipped)
    print("faults:", len(e.faults))
