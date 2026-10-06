# assets/ — 资源层

| 目录 | 内容 | 入库 |
|---|---|---|
| `apk/` | 原始样本 `base.apk`（43 MB，只读基线） | 否（`.gitignore`） |

## `assets/assets/apk/base.apk`

| 项 | 值 |
|---|---|
| 包名 | `com.tudou.tool`（囧次元） |
| versionName | `1.5.8.0` |
| 引擎 | Flutter / Dart AOT 3.6.0（arm64-v8a） |
| 大小 | 43,041,159 字节 |
| SHA256 | `AC170C12F20107533342BC32798564FB13BDA95EB0624ABB64DF30F886C5CBB9` |
| 权限 | 只读（`-r--r--r--`） |

**这是全部解包/反编译产物的唯一来源**，请勿修改。由它可重建：

```bash
java -jar tools/apktool.jar d assets/assets/assets/apk/base.apk -o /tmp/base_decoded   # lib/arm64-v8a/*.so
java -jar tools/jadx/bin/jadx -d /tmp/jadx_src assets/assets/assets/apk/base.apk       # Java 源码
```

## 相关

- 工具链在根目录 [`tools/`](../tools/README.md)（第三方，不入库，由 `pnpm tools:install` 恢复）
- 产物重建步骤见 [`../research/README.md`](../research/README.md)
