# -*- coding: utf-8 -*-
"""jcy_protocol.auth — 囧次元 ``authentication`` 请求头生成算法。

算法（已由运行时实测与服务端实测确认）::

    authentication = CUSTOM_B64( E( CUSTOM_B64( S ) ) )

    S = "{code_version}-{ts}-Android-{app_version}-{device_fp}-{client_appid}"

长度关系::

    S(78B) --CUSTOM_B64--> A1(104B) --E--> BODY(112B) --CUSTOM_B64--> AUTH(152 字符)

``BODY`` 结构::

    BODY[  0: 16] = ct0       恒定 23754ae9d0cbe749f5441e769b45143e
    BODY[ 16: 48] = O[0:32]   服务端实际校验的部分，只依赖 ts
    BODY[ 48:112] = O[32:96]  依赖 device_fp 等

本模块只实现**纯逻辑部分**（字母表编解码、输入串构造、body 解析、头拼装）与
分组密码的**后端接口**；具体 ``E`` 由调用方注入（见 :class:`EBackend`）。
这样 ``src/`` 保持零外部大文件依赖，符合仓库分层约定。

算法原理与判定依据见 ``docs/algorithm-auth.md``。
"""
from __future__ import annotations

import base64
from typing import Protocol, runtime_checkable

__all__ = [
    "ALPHABET",
    "STD_B64",
    "CODE_VERSION",
    "APP_VERSION",
    "CLIENT_APPID",
    "APPID_HEADER",
    "AES_KEY",
    "AES_IV",
    "CT0",
    "custom_b64",
    "custom_b64d",
    "build_input",
    "body_of",
    "split_body",
    "EBackend",
    "generate",
    "generate_parsed",
]

# ---------------------------------------------------------------- 常量

#: 自定义 base64 字母表（标准字母表第 i 个字符 → 本表第 i 个字符）
ALPHABET = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj"

#: 标准 base64 字母表
STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

#: 输入串固定字段
CODE_VERSION = "3.0.0.8"
APP_VERSION = "1.5.8.0"
CLIENT_APPID = "default"

#: 请求头 ``appid``
APPID_HEADER = "4150439554430529"

#: 分组密码参数（取自 libcore.so 数据段，随安装实例固定）
AES_KEY = b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"   # 32 字节
AES_IV = b"WonrnVkxeIxDcFbv"                    # 16 字节

#: ``BODY`` 恒定前缀（前 16 字节）
CT0 = bytes.fromhex("23754ae9d0cbe749f5441e769b45143e")

_TO_CUSTOM = str.maketrans(STD_B64, ALPHABET)
_TO_STD = str.maketrans(ALPHABET, STD_B64)


# ---------------------------------------------------------------- 编码

def custom_b64(data: bytes) -> str:
    """标准 base64 后按 :data:`ALPHABET` 重映射字母表。"""
    return base64.b64encode(data).decode().translate(_TO_CUSTOM)


def custom_b64d(text: str) -> bytes:
    """:func:`custom_b64` 的逆运算。"""
    return base64.b64decode(text.translate(_TO_STD))


# ---------------------------------------------------------------- 输入串

def build_input(ts: int, device_fp: str) -> str:
    """构造送进管线的输入串 ``S``（78 字节）。

    :param ts: 毫秒时间戳，必须与请求头 ``ts`` 一致
    :param device_fp: 设备指纹（32 位十六进制），随安装实例变化
    """
    return "%s-%d-Android-%s-%s-%s" % (
        CODE_VERSION, ts, APP_VERSION, device_fp, CLIENT_APPID)


# ---------------------------------------------------------------- body

def body_of(auth: str) -> bytes:
    """从 ``authentication`` 头解出 112 字节 ``BODY``。"""
    return custom_b64d(auth)


def split_body(body: bytes) -> dict:
    """把 ``BODY`` 拆成有语义的片段。

    :return: ``{"ct0", "o32", "o64", "o96"}``（均为 bytes）
    """
    if len(body) != 112:
        raise ValueError("BODY 长度应为 112，实际 %d" % len(body))
    return {
        "ct0": body[0:16],     # 恒定前缀
        "o32": body[16:48],    # 服务端校验的 32 字节
        "o64": body[16:80],    # 确定性部分
        "o96": body[16:112],   # 完整 O
    }


# ---------------------------------------------------------------- E 后端

@runtime_checkable
class EBackend(Protocol):
    """分组密码 ``E`` 的后端接口。

    输入 104 字节（``A1``），输出 112 字节（``BODY``）。

    实现方需保证：CBC 模式、16 字节分组、明文补齐至 112 字节、
    key/iv 取 :data:`AES_KEY` / :data:`AES_IV`。
    """

    def encrypt(self, a1: bytes) -> bytes:
        ...


# ---------------------------------------------------------------- 主流程

def generate(ts: int, device_fp: str, backend: "EBackend") -> str:
    """生成 ``authentication`` 头。

    :param ts: 毫秒时间戳
    :param device_fp: 设备指纹
    :param backend: 提供 ``E`` 的后端（见 :class:`EBackend`）
    :return: 152 字符的 ``authentication`` 头
    """
    a1 = custom_b64(build_input(ts, device_fp).encode()).encode()
    body = backend.encrypt(a1)
    if len(body) != 112:
        raise ValueError("E 输出长度应为 112，实际 %d" % len(body))
    return custom_b64(body)


def generate_parsed(ts: int, device_fp: str, backend: "EBackend") -> dict:
    """同 :func:`generate`，但一并返回解析后的结构（便于自检与调试）。"""
    auth = generate(ts, device_fp, backend)
    body = body_of(auth)
    return {
        "ts": ts,
        "device_fp": device_fp,
        "input": build_input(ts, device_fp),
        "a1": custom_b64(build_input(ts, device_fp).encode()),
        "auth": auth,
        "body": body,
        **split_body(body),
    }
