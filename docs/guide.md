# DSH 插件兼容层 — 使用指南

本插件让 YUI 能使用 **DeepSeek Harness（DSH）** 生态的插件与技能。

## 快速上手

### 1. 安装 DSH 技能

对模型说：

> 用 dsh_install 从 github:wmengxiang/dsh-any-skills 安装 DSH 技能

或：

> 从 npm 安装 DSH 技能：npm:@scope/包名

首次安装会先给出免责声明，回复"我已知晓并同意"后继续。

### 2. 查看已装技能

> 列出已安装的 DSH 技能（dsh_list）

### 3. 使用技能

> 加载 DSH 技能 X（dsh_load）

模型会读取技能的说明与正文指令，然后按指令执行。

### 4. 安全审计

> 审计 DSH 技能 X 是否安全（dsh_audit）

### 5. 卸载

> 卸载 DSH 技能 X（dsh_uninstall）

卸载移入 `.trash-<时间戳>-<名称>`，误删可在数据目录手动恢复。

## 数据位置

- 技能库：`%LOCALAPPDATA%\N.E.K.O\dsh_compat\skills`
- 兼容读取（只读）：`~/.dsh/skills`（DSH 原生技能目录）

## 注意事项

- **函数型 DSH 插件**（`apply(ctx)` 的 TS 包）需要 DSH 运行时，本插件不直接执行；
  用 `dsh_plugin_info` 查看它的包结构与说明。
- 技能内容是第三方数据，模型需自行判断如何执行，不盲目照做。
- 只允许从 GitHub / npm 官方域名下载，其他来源会被拒绝。
