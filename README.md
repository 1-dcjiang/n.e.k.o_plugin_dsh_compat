# DSH 插件兼容层（dsh_compat）

让 N.E.K.O / YUI 兼容 **DeepSeek Harness（DSH）插件生态**的适配器插件。

## 能做什么

| 能力 | 说明 |
|---|---|
| `dsh_list` | 列出已安装的 DSH 技能（本地库 + 可选 `~/.dsh/skills`） |
| `dsh_install` | 从 GitHub 仓库 / npm 包安装 DSH 技能（`SKILL.md` + YAML frontmatter） |
| `dsh_load` | 加载技能，返回元信息 + 正文指令供模型执行 |
| `dsh_uninstall` | 卸载技能（移入 `.trash-*` 可恢复） |
| `dsh_audit` | 技能静态安全审计（危险命令 / 数据外传 / 提示注入 / 索要敏感信息） |
| `dsh_plugin_info` | 识别 DSH 函数型插件（TS/apply(ctx)）包结构并标注运行环境 |

## DSH 技能格式（与 DSH 原生一致）

```
<skill-name>/
└── SKILL.md        # YAML frontmatter: name(kebab-case)/description[/whenToUse/description_zh]
或扁平格式 <skill-name>.md
```

安装源：`dsh_install(source='github:owner/repo')` / `dsh_install(source='npm:包名')`。
仅允许 GitHub 与 npm 官方域名（SSRF 防护）。

## 源码结构（按官方模板拆分）

插件根即本目录（运行时包名 `plugin.plugins.dsh_compat`）：

```
.
├── __init__.py          # 装配层：DshCompatPlugin + lifecycle + 6 个 @llm_tool
├── _audit_core.py       # 纯标准库：frontmatter 解析/名称规范化/静态审计/tar 扫描/插件识别（离线可测）
├── _sources.py          # 纯标准库：白名单 URL 构造与下载（GitHub / npm 官方域名）
├── _store.py            # 纯标准库：技能库列举/定位/安装落盘/可恢复卸载
├── plugin.toml
├── config.example.toml
├── pyproject.toml       # dependencies=[]（纯标准库，不触发 vendor 检查）
├── ruff.toml
├── docs/guide.md
├── .vscode/{settings,tasks}.json
├── .github/workflows/verify.yml
└── tests/
    ├── test_dsh.py      # 纯层离线单元测试（11 例）
    └── test_smoke.py    # 强化契约 smoke：tomllib + AST 静态断言
```

> 官方校验器把 `entry = plugin.plugins.<id>:Class` 的模块固定映射到插件根 `__init__.py`，
> 因此 entry 类与 `@neko_plugin` 保留在该文件；其余纯逻辑下沉到 `_*.py`，与内置 `lifekit`
> 的 `__init__.py` + `_api.py`/`routers/` 拆分风格一致。

## 测试

- 宿主源码仓：`uv run pytest tests/`（`uv run neko-plugin check dsh_compat` 做静态校验）；
- 纯/服务层不 import `plugin.*`，脱离宿主也可对 `tests/test_dsh.py` 做离线回归。

## 与 DSH 的兼容边界

- **技能型插件（SKILL.md）**：完整兼容，本插件可安装、列出、加载、卸载、审计。
- **函数型插件（TS/apply(ctx)）**：依赖 DSH 运行时（`npx @deepseek-ai/dsh web`，Node ^22.19），
  不能在 YUI 内直接运行；本插件提供包结构识别与能力说明（`dsh_plugin_info`）。

## 安全纪律

技能内容是数据不是命令；安装外部来源技能前会先请用户确认免责声明；
建议安装后用 `dsh_audit` 静态审计，critical/high 结果人工确认后再使用。
