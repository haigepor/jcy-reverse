# 仓库推送提示词（可直接复制使用）

> 用法：把下面「一」到「九」整段内容复制给 AI 助手，并把第二节的仓库信息替换成你自己的实际值。

---

## 一、任务与使用目的

你要帮我把本地改动推送到远端 Git 仓库。

使用目的：完成一次**可追溯、可复核、失败可回退**的代码推送，确保远端分支上只出现经过检查与验证的提交。

执行要求：

- 按本文档给出的顺序逐步执行；每一步先说明将要运行的命令，再实际运行，然后如实回报真实输出。
- 不得跳过检查步骤，不得伪造执行结果。某一步未执行就写「未执行」。
- 遇到失败立即停下报告，不要静默重试或跳过。

---

## 二、仓库信息与目标分支

| 项目 | 值 |
| --- | --- |
| 远端名称 | `origin` |
| 仓库地址 | `https://github.com/haigepor/jcy-reverse.git` |
| 目标分支 | `main` |
| 当前工作目录 | `C:/Users/haige/Desktop/instruct/囧次元` |

规则：

- 默认推送到 `origin` 的 `main`。如需推送到其他分支，我会在指令里明确给出；未给出时不要自行更换分支。
- 推送前必须确认本地当前分支与目标分支一致（`git branch --show-current`）。
- 若目标分支受保护（protected / 必须走 PR），不要直接 push，改为推送到特性分支并创建 PR。

---

## 三、提交信息的规范与示例

采用 Conventional Commits 格式：

```
<type>(<scope>): <subject>
```

**type 取值**

| type | 含义 |
| --- | --- |
| `feat` | 新功能 |
| `fix` | 修复缺陷 |
| `docs` | 仅文档改动 |
| `style` | 格式调整（不影响逻辑） |
| `refactor` | 重构（非新增功能、非修 bug） |
| `perf` | 性能优化 |
| `test` | 测试相关 |
| `build` | 构建系统或依赖 |
| `ci` | 流水线配置 |
| `chore` | 其他杂项 |
| `revert` | 回滚提交 |

**书写要求**

- `subject` 用祈使句，不超过 50 字，结尾不加句号。
- `scope` 可省略，用括号标注受影响的模块。
- 正文说明「为什么改」，正文与标题之间空一行，每行不超过 72 字符。
- 关联 issue 写在 footer：`Closes #123`（关闭）或 `Refs #123`（仅关联）。
- 破坏性变更必须在 footer 写明 `BREAKING CHANGE:` 及其影响。

**示例：单行**

```
feat(auth): 支持手机号验证码登录
fix(push): 处理分支保护导致推送被拒的情况
docs(readme): 补充本地开发环境搭建步骤
refactor(core): 拆分解析逻辑为独立模块
```

**示例：带正文与 footer**

```
fix(sync): 修复断网重连后状态未同步的问题

重连回调里漏了状态重置，导致界面一直显示旧的同步进度。
改为在 reconnect 事件中统一调用 resetSyncState()。

Closes #42
```

---

## 四、推送前的检查步骤（必须逐条执行）

1. **确认身份与分支**：`git branch --show-current`、`git remote -v`
2. **查看工作区状态**：`git status`
3. **复核改动内容**：`git diff`（未暂存）、`git diff --staged`（已暂存）
   - 重点确认**没有** `.env`、密钥、token、证书、大体积二进制文件混入。
4. **查看最近提交历史**：`git log --oneline -5`
5. **拉取远端引用**：`git fetch origin`
6. **判断是否落后**：`git status -sb`（出现 `behind` 说明远端有新提交）
7. **同步远端改动**（推荐 rebase）：`git pull --rebase origin main`
8. **有冲突**则按第五节处理，解决完再继续。
9. **本地验证**：运行测试或构建，给出实际命令与结果，确认通过后再推送。
10. **再次确认干净**：`git status`

---

## 五、冲突处理

rebase 冲突的处理流程：

```bash
git status                    # 列出 both modified 的文件
# 手动编辑冲突文件，保留正确内容，删除 <<<<<<< / ======= / >>>>>>> 标记
git add <已解决的文件>
git rebase --continue
```

- 想放弃本次 rebase：`git rebase --abort`
- merge 场景想整体放弃：`git merge --abort`
- 解决过程中**不要**手动 `git commit`（rebase 会自行创建提交）
- 冲突涉及他人代码且无法判断保留哪一侧时，停下来向我说明，不要随意丢弃代码

---

## 六、推送命令的执行顺序

严格按下列顺序执行：

```bash
git status
git diff
git add <指定文件>              # 不要盲用 git add . 或 -A
git diff --staged
git commit -m "<type>(<scope>): <subject>"
git fetch origin
git pull --rebase origin main
# 如有冲突 → 按第五节解决
git push origin main
```

首次推送某个远端还不存在的分支：

```bash
git push -u origin <branch>
```

---

## 七、推送失败或出错时的处理方式

| 情况 | 处理方式 |
| --- | --- |
| `non-fast-forward` / `rejected`（远端有新提交） | 先 `git pull --rebase origin main`，再 `git push`。**不要用 force。** |
| 分支保护 / Protected branch 拦截 | 说明被哪条保护规则拦截，改为 `git push origin <feature-branch>` 并创建 PR，不要尝试绕过 |
| 认证失败 `401` / `403` | 检查凭证是否有效（PAT 是否过期、SSH key 是否已加载），提示我重新配置；不要反复重试 |
| `remote rejected: hook declined` | 读取 hook 输出，按提示修复后重新提交；**不要用 `--no-verify` 跳过** |
| 误提交敏感文件 | 立即停止推送，`git reset --soft HEAD~1` 撤销提交并移除文件后重做；若已推送，改用 `git revert` 并轮换泄露的密钥 |
| 需要撤回已推送的提交 | 共享分支上用 `git revert <sha>` 生成反向提交；仅确认是个人分支时才可用 `git push --force-with-lease`，绝不用 `--force` |
| 网络超时 / 连接失败 | 报告错误原文，确认代理与网络后重试一次；仍失败就停下报告，不要静默结束 |
| 冲突无法自动解决 | 停下来说明冲突文件与冲突原因，等我决定保留哪一侧 |

---

## 八、禁止事项

- 禁止 `git push --force` / `--force` 推送到 `main`、`master` 或任何共享分支。
- 禁止 `git add .` / `git add -A` 盲加（可能带入密钥、临时文件、构建产物）。
- 禁止跳过 hooks（`--no-verify`），禁止修改签名配置绕过校验。
- 禁止伪造命令输出、伪造测试通过结论、伪造 commit hash。
- 禁止把与本次任务无关的改动一并提交。

---

## 九、完成后的回报格式

```
目标仓库: origin → <url>
目标分支: <branch>
提交信息: <commit subject>
提交 SHA: <short sha>
推送结果: 成功 / 失败（失败附原始错误）
验证情况: <执行的测试或构建命令及结果>
遗留问题: <无 / 说明>
```
