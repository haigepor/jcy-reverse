# 囧次元 (com.tudou.tool) 逆向文档

Flutter 壳 + 自研加密协议的视频 App 完整逆向工程文档。
目标: versionName 1.5.8.0 (Dart 3.6.0 / Flutter 3.27.x)。

## 成果速览

| 目标 | 状态 |
|---|---|
| 视频播放接口全链路分析 | ✅ 端点/参数/头/链路全部还原 |
| 登录逻辑 (设备静默登录) | ✅ device-base + X-Token 机制 |
| API 加解密逆向 | ✅ 监控/信令双通道 100%; HTTP 结构 100%, 会话 key 运行时项 |
| 示例页 | ✅ out/demo/index.html (hls.js) |
| 离线客户端库 | ✅ out/client/gg_client.py (已验证加密层) |

## 密钥速查

| 通道 | 算法 | key | iv |
|---|---|---|---|
| 监控 (libcore C2) | AES-128-CBC PKCS7 | `qPwClBj7j7ZQraSm` | `p3JdVQl3q7WQJIgG` |
| 信令 (libloader IPC) | AES-128-CBC PKCS7 | `kFGTbLlOzFHQCIKp` | `F3q22XoM8l6T2Ydc` |
| HTTP body | 随机会话 key AES-CBC + RSA-2048 包裹 | 每请求随机 | 每请求随机 |

## 快速上手

```python
import sys; sys.path.insert(0, 'out/client')
from gg_client import SIG_KEY, SIG_IV, channel_decrypt

# 解一条真实信令响应
print(channel_decrypt(
    "VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L"
    "3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY=", SIG_KEY, SIG_IV))
# b'{"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}'
```

## 文档导航

- **加密算法**: 三通道架构 / 监控通道 / 信令通道 / HTTP body / X-Token
- **接口文档**: 总览与请求头 / 视频列表 / 播放链接 / 设备登录 / 端点速查
- **解密过程全记录**: 破解放事 (完整时间线) / 工具链手册 / 证据索引 / 遗留问题

## 本地阅读

```bash
cd docs
python -m http.server 3000
# 浏览器打开 http://localhost:3000 (docsify 从 CDN 加载渲染器)
# 或: npx serve .
```

## 仓库关键路径

```
docs/                 本文档站
apk/base.apk          原始样本 (SHA256 AC170C12..., 未动)
out/API_ANALYSIS.md   分析主文档 (静态+动态)
out/VERIFICATION.txt  审计链 (两阶段)
out/client/           Python 客户端 + frida 脚本族
out/blutter_out/      blutter 产物 (pp.txt 对象池 / asm / frida 模板)
out/demo/index.html   离线验证页
out/auth_samples.json 真机抓包样本 (88 条)
reflutter_work/       dump.dart / 组合包 APK
```
