# tests/ — 测试层

```bash
pnpm test                                                    # 全量（协议 + 结构校验）
./.venv/Scripts/python.exe tests/test_channels.py            # 协议向量回归
./.venv/Scripts/python.exe tests/test_authgen.py             # authgen 算法回归
```

| 文件 | 覆盖 | 依赖 |
|---|---|---|
| `test_channels.py` | 监控 / 信令两条 AES 通道的加解密向量回归 | `pycryptodome`、`src/jcy_protocol` |
| `test_authgen.py` | `authentication` 生成算法 5 项断言 | `unicorn`、`research/artifacts/`、`research/deliverables/authgen.py` |
| `fixtures/authgen_vector.json` | 固化的真机向量 | — |

## `test_authgen.py` 的判据

对 `ts = 1790618586109`（取自 2026-09-29 真机抓包）：

1. `authentication` 头长度 = 152
2. 解码后 `BODY` 长度 = 112
3. `BODY[0:16]` == `23754ae9d0cbe749f5441e769b45143e`（恒定前缀）
4. `BODY[16:48]` == `2b3ef9d5b6c78fd91e33fb5136486918f70e50af61d497be95acdd0fd7ffae85`
   （服务端实际校验的 32 字节）
5. 头前 24 字符与真机抓包一致

> 该抓包实例的 `device_fp` 与当前 `research/artifacts/` 设备镜像**不同源**，
> 因此只固化与 `device_fp` 无关的 `ct0` 与 `O[0:32]`。
> 详见 [`../docs/algorithm-auth.md`](../docs/algorithm-auth.md) §6.3。

## 跳过语义

`test_authgen.py` 在 `research/artifacts/` 缺失（未重建大二进制）时以退出码 **77** 退出，
表示 SKIP 而非 FAIL。CI 与本地可据此区分「未准备环境」与「回归失败」。
