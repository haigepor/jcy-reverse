# Apipost「囧次元」接口库详情汇总

- project_id: `6ef0f75d8470000`
- 接口数: 35

## 频道列表  `GET`

- URL: `http://43.145.33.254:27990/app/channel?top-level=true`
- target_id: `6ef0f79ac072000`
- 说明: 首页频道聚合入口。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】V6轮(2026-09-29): 200 P0.P1 ACCEPTED(重放窗口内); 
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f79ac072000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 频道列表(301跳转源)  `GET`

- URL: `http://43.145.33.254:27990/app/channel/`
- target_id: `6ef0f7a3c472000`
- 说明: 实际抓包 app 先请求 /app/channel/?top-level=true, 服务端 301 → /app/channel?top-level=true (Location头)。明文跳转。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authen
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f7a3c472000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 全局配置  `GET`

- URL: `http://43.145.33.254:27990/app/config`
- target_id: `6ef0f7ad4072000`
- 说明: App 全局配置(弹窗/开关等), 响应 P0.P1 密文约 2917B。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】V6轮(2026-09-29): 200 P0.
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f7ad4072000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 频道配置  `POST`

- URL: `http://43.145.33.254:27990/app/config/channel`
- target_id: `6ef0f7b6c070000`
- 说明: 频道页配置上报/拉取, 请求体 P0.P1(48B明文), 响应 517-561B。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】本轮重放 auth age>窗口 → 
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f7b6c070000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 视频页配置  `POST`

- URL: `http://43.145.33.254:27990/app/config/video`
- target_id: `6ef0f7c05c70000`
- 说明: 播放器/视频页配置, 请求体 P0.P1(48B明文)。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】2026-09-29 13:0x 复放: 200 OK(auth 
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f7c05c70000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## Banner(频道0/首页)  `GET`

- URL: `http://43.145.33.254:27990/app/banners/0`
- target_id: `6ef0f7ca5870000`
- 说明: 按 top-level 频道ID取 banner 列表, 实测触发 ID: 0/1/2/3/26。响应 P0.P1 约 7506B。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f7ca5870000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## Banner(频道1)  `GET`

- URL: `http://43.145.33.254:27990/app/banners/1`
- target_id: `6ef0f7d3f872000`
- 说明: 频道1(日漫) banner。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】2026-09-29 13:0x 复放: 200 实抓(13:07新鲜)(auth 新鲜)。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f7d3f872000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## Banner(频道2)  `GET`

- URL: `http://43.145.33.254:27990/app/banners/2`
- target_id: `6ef0f7dd3870000`
- 说明: 频道2(國漫) banner。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】2026-09-29 13:07 实抓新鲜。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f7dd3870000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 视频列表  `GET`

- URL: `http://43.145.33.254:27990/app/video/list`
- target_id: `6ef0f7e6b072000`
- 说明: 核心列表接口。明文结构 total=2142, items[]×18字段(id/name/ename/score/hits/addtime/tag/cover/...)。支持 channel=0..26, sort=weight|hits|addtime, limit, page 分页。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decryp
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f7e6b072000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 视频详情  `GET`

- URL: `http://43.145.33.254:27990/app/video/detail`
- target_id: `6ef0f7f07c70000`
- 说明: 单部番剧详情, 明文18字段(黑暗机器 id=113490 样本)。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】V6轮(2026-09-29): 200 P0.P1 
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f7f07c70000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 搜索  `GET`

- URL: `http://43.145.33.254:27990/app/video/search`
- target_id: `6ef0f7fa1c70000`
- 说明: 关键词搜索, UI实测"ai"返回3结果。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】V6轮(2026-09-29): 200 P0.P1 ACCEPTED(重放窗口
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f7fa1c70000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 搜索联想  `GET`

- URL: `http://43.145.33.254:27990/app/video/key`
- target_id: `6ef0f8037c70000`
- 说明: 搜索框联想词(与 search 同时触发)。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】V6轮实抓; 本轮 188s 重放 403502(窗口边界数据点)。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8037c70000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 更新排期表  `GET`

- URL: `http://43.145.33.254:27990/app/video_update_list/2026-09-29`
- target_id: `6ef0f80d0872000`
- 说明: 按日期取更新排期, 路径参数 yyyy-mm-dd。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】本轮重放 auth age>窗口 → 403502 (预期行为, 非接
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f80d0872000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 设备信息上报  `POST`

- URL: `http://43.145.33.254:27990/app/video/device-base`
- target_id: `6ef0f815e872000`
- 说明: 播放前设备信息上报, 请求体 P0.P1(16B明文)。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】2026-09-29 13:0x 复放: 200 OK(auth 
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f815e872000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 播放记录上报  `POST`

- URL: `http://43.145.33.254:27990/app/video/record`
- target_id: `6ef0f81f4872000`
- 说明: 观看进度/记录上报, 请求体 P0.P1(96B明文)。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】2026-09-29 13:0x 复放: 200 OK(auth 
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f81f4872000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 播放连接  `POST`

- URL: `http://43.145.33.254:27990/app/video/play-connect`
- target_id: `6ef0f828a472000`
- 说明: 点立即播放先触发, 与 /app/video/play 成对出现。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】2026-09-29 13:0x 复放: 200 OK(
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f828a472000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 播放凭证  `POST`

- URL: `http://43.145.33.254:27990/app/video/play`
- target_id: `6ef0f831e070000`
- 说明: 返回播放直链+一次性凭证: 明文含 url(http://yh.jx.xajtl.com/vo1v03.php?...&t=) 与 x-time/x-sign1/x-sign2/x-form 请求头组; 直链仅一次有效(Range 0-63 实测 206, ftypisom); 重放 play 的 authentication 换取的凭证不可复用。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f831e070000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 弹幕拉取  `GET`

- URL: `http://43.145.33.254:27990/app/danmu`
- target_id: `6ef0f83b0c70000`
- 说明: 播放中每60s轮询。实测参数 start_time_point/end_time_point(毫秒)。V6结论修正: 参数名非 start_t。auth 可被接受但业务码恒 20000 —— 推测与播放会话/种子绑定, 语义未明。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f83b0c70000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 热评置顶  `GET`

- URL: `http://43.145.33.254:27990/app/vod_comment/gettop`
- target_id: `6ef0f8444472000`
- 说明: 评论置顶/最热。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】本轮重放 auth age>窗口 → 403502 (预期行为, 非接口异常)。 V6轮实抓+内存明文。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8444472000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 热评命中  `GET`

- URL: `http://43.145.33.254:27990/app/vod_comment/gethitstop`
- target_id: `6ef0f84ddc72000`
- 说明: 评论命中统计。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】本轮重放 auth age>窗口 → 403502 (预期行为, 非接口异常)。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f84ddc72000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 评论列表  `GET`

- URL: `http://43.145.33.254:27990/app/vod_comment/getlist`
- target_id: `6ef0f8571c70000`
- 说明: 评论分页, 明文字段 id/pid/oid/vid/vname/content。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】本轮重放 auth age>窗口 → 40
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8571c70000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 清图上报  `POST`

- URL: `http://43.145.33.254:27990/app/users/clearimg`
- target_id: `6ef0f8606470000`
- 说明: 用户行为上报, 请求体 P0.P1(64B明文)。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】2026-09-29 13:0x 复放: 200 OK(auth 新鲜)
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8606470000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 用户任务  `POST`

- URL: `http://43.145.33.254:27990/app/users/task`
- target_id: `6ef0f86a5870000`
- 说明: 任务系统状态拉取/上报, 请求体 P0.P1(48B明文)。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】2026-09-29 13:0x 复放: 200 OK(aut
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f86a5870000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 观看历史  `POST`

- URL: `http://43.145.33.254:27990/app/history`
- target_id: `6ef0f8745072000`
- 说明: 观看历史, 请求体 P0.P1(48B明文)。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】本轮重放 auth age>窗口 → 403502 (预期行为, 非接口异常
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8745072000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 本地缓存上报  `POST`

- URL: `http://43.145.33.254:27990/app/history/localcahce`
- target_id: `6ef0f87da870000`
- 说明: 注意路径拼写 localcahce(官方拼写如此)。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】2026-09-29 13:0x 复放: 200 OK(auth 新鲜
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f87da470000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 签到规则  `GET`

- URL: `http://43.145.33.254:27990/app/task/sign_rule`
- target_id: `6ef0f8873072000`
- 说明: 任务中心连签奖励规则(第1天10 …第30天300)。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】2026-09-29 13:0x 复放: 200 实抓(13:08新
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8873072000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 收件箱  `POST`

- URL: `http://43.145.33.254:27990/app/messagebox/give_me`
- target_id: `6ef0f8908072000`
- 说明: 消息收件箱拉取。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】2026-09-29 13:0x 复放: 200 OK(auth 新鲜)。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8908072000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 动态消息  `POST`

- URL: `http://43.145.33.254:27990/app/messagebox/dynamic`
- target_id: `6ef0f89a6c72000`
- 说明: 动态/系统通知。【加密方案】请求体与响应体均为 `<P0_b64>.<P1_b64>` 双段结构: P0=RSA-2048 公钥包裹的逐请求会话密钥(b64解码后256B), P1=AES-CBC 密文(b64)。RSA 私钥仅运行时存在(内存态), 离线无法解 P0; 明文提取走 frida 内存扫描 (out/decrypt_v5/mem_plaintext.py, 解密后明文在堆内存驻留约15s)。authentication 签名同样客户端本地生成(CBC 传播特征证实)。【实测】本轮重放 auth age>窗口 → 403502 (预期行为, 非接口异常)。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f89a6c72000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 升级检查(特例)  `POST`

- URL: `http://43.145.33.254:27990/app/upgrade`
- target_id: `6ef0f8a39472000`
- 说明: 全套方案例外: 头为大写 Authentication(另一魔数 905b5ed3…), 请求体为 216B 裸二进制(无点分隔), 非 P0.P1 方案。频率高(app 轮询)。【实测】HTTP 200, 响应 1196B; 与 V5 一致。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8a39472000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## Host 配置(v2 方案)  `GET`

- URL: `http://43.145.33.254:27990/app/v2/config/host`
- target_id: `6ef0f8acb070000`
- 说明: V5 抓包记录: authentication 使用第三种魔数 e9e3af6a…(方案绑端点)。游客环境未复现触发, 待登录态验证。【实测】仅 V5 记录, 本轮未触发(未执行)。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8acac70000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 用户信息(登录后)  `GET`

- URL: `http://43.145.33.254:27990/app/users/info`
- target_id: `6ef0f8b63872000`
- 说明: 游客 token 调用被拒/无有效响应, 需登录态。【实测】游客不可测(未执行)。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8b63872000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## VIP 价格(登录后)  `GET`

- URL: `http://43.145.33.254:27990/app/vip_price/list`
- target_id: `6ef0f8bf8070000`
- 说明: 需登录态, V6轮未触达。【实测】未执行。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8bf8070000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 任务列表(登录后)  `POST`

- URL: `http://43.145.33.254:27990/app/task/task`
- target_id: `6ef0f8c86070000`
- 说明: 需登录态, 与 users/task 不同。【实测】未执行。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8c86070000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 播放地址v4(登录后)  `GET`

- URL: `http://43.145.33.254:27990/app/playaddr/v4/client`
- target_id: `6ef0f8d19870000`
- 说明: 需登录态; 游客播放走 /app/video/play。【实测】未执行。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8d19870000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

## 短信验证码(登录)  `POST`

- URL: `http://43.145.33.254:27990/app/login/smscode`
- target_id: `6ef0f8dab470000`
- 说明: 登录入口, 触发需手机号与验证码流程, 未自动化。【实测】未执行。
- request: `{"auth": {"type": "inherit"}, "body": {"mode": "none", "parameter": [], "raw": "", "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}}, "pre_tasks": [], "post_tasks": [], "header": {"parameter": [{"param_id": "6ef0f8dab470000", "description": "应用ID, 恒定", "field_type": "string", "is_checked": 1, "key": "appid", "not_null": 1, "value": "4150439554430529", "schema": {"type": "string"`
- response: `{"example": [{"example_id": "1", "raw": "", "raw_parameter": [], "headers": [], "expect": {"code": "200", "content_type": "json", "is_default": 1, "mock": "", "name": "成功", "schema": {"type": "object"}, "verify_type": "schema", "sleep": 0}}], "is_check_result": 1}`
- 其它字段: target_id, project_id, parent_id, target_type, version, sort, protocol, mark_id, tags

