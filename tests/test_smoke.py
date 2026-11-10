"""强化版 smoke 契约测试（离线，不 import 宿主 SDK）。

覆盖官方静态校验器可由标准库复现的关键契约：
1. plugin.toml 必填字段 / entry 模块与类命名合法；
2. config.example.toml 存在、不含 [plugin]、runtime timeout 合法；
3. pyproject.toml 纯标准库（dependencies 为空，豁免 vendor 检查）；
4. entry 类 DshCompatPlugin 继承 NekoPluginBase 且带 @neko_plugin，
   6 个 @llm_tool 工具名与 2 个 @lifecycle 齐全合法；
5. 必备文件存在、无 requirements.txt、源码树无 symlink；
6. 纯/服务层模块可独立导入，且不依赖 plugin.* SDK。

在宿主源码仓可用 `uv run pytest tests/`；本机无 SDK 环境也能直接运行本文件。
"""
from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "__init__.py"
EXPECTED_TOOLS = {
    "dsh_list",
    "dsh_load",
    "dsh_install",
    "dsh_uninstall",
    "dsh_audit",
    "dsh_plugin_info",
}
EXPECTED_LIFECYCLES = {"startup", "shutdown"}


def _load_toml(rel: str) -> dict:
    with open(ROOT / rel, "rb") as f:
        return tomllib.load(f)


def _call_kwargs(node: ast.Call) -> dict:
    out = {}
    for kw in node.keywords:
        if isinstance(kw.value, ast.Constant):
            out[kw.arg] = kw.value.value
    return out


# ---------- plugin.toml ----------
def test_plugin_toml_required_fields():
    data = _load_toml("plugin.toml")
    plugin = data["plugin"]
    assert plugin["id"] == "dsh_compat"
    assert re.match(r"^\d+\.\d+\.\d+.*$", plugin["version"])
    assert plugin["type"] == "plugin"
    entry = plugin["entry"]
    assert re.match(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$", entry)
    module, class_name = entry.split(":")
    assert module == "plugin.plugins.dsh_compat"
    assert class_name == "DshCompatPlugin"
    assert data.get("plugin", {}).get("sdk", {}).get("recommended")
    assert data["plugin"]["author"]["name"]


# ---------- config.example.toml ----------
def test_config_example_present_and_no_plugin_table():
    example = _load_toml("config.example.toml")
    assert "plugin" not in example, "config.example.toml 不得包含 [plugin] 段"
    runtime = example["plugin_runtime"]
    assert runtime["enabled"] is True
    assert runtime["auto_start"] is True
    timeout = runtime.get("timeout")
    assert isinstance(timeout, int) and 1 <= timeout <= 300


# ---------- pyproject.toml（纯标准库，无外部依赖 → 不触发 vendor 检查） ----------
def test_pyproject_declares_empty_dependencies():
    project = _load_toml("pyproject.toml")["project"]
    assert project["name"]
    assert project["version"] == "0.1.0"
    assert project.get("dependencies", []) == []


# ---------- entry 类 / 装饰器注册 ----------
def test_entry_class_and_registered_tools_lifecycles():
    tree = ast.parse(ENTRY.read_text(encoding="utf-8"))
    plugin_class: ast.ClassDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "DshCompatPlugin":
            plugin_class = node
            break
    assert plugin_class is not None, "缺少 DshCompatPlugin 类"
    base_names = {b.id for b in plugin_class.bases if isinstance(b, ast.Name)}
    assert "NekoPluginBase" in base_names
    class_decorators = {
        d.id for d in plugin_class.decorator_list if isinstance(d, ast.Name)
    }
    assert "neko_plugin" in class_decorators

    tools, lifecycles = set(), set()
    for member in plugin_class.body:
        if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in member.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Name):
                continue
            kwargs = _call_kwargs(dec)
            if dec.func.id == "llm_tool":
                tools.add(kwargs.get("name"))
            elif dec.func.id == "lifecycle":
                lifecycles.add(kwargs.get("id"))
    assert tools == EXPECTED_TOOLS
    assert lifecycles == EXPECTED_LIFECYCLES


# ---------- 文件布局 / 禁用件 ----------
def test_required_files_and_no_requirements_or_symlink():
    required = (
        "README.md",
        "docs/guide.md",
        "tests/test_dsh.py",
        "config.example.toml",
        "pyproject.toml",
        "ruff.toml",
        ".gitignore",
    )
    for rel in required:
        assert (ROOT / rel).is_file(), f"缺少 {rel}"
    assert not (ROOT / "requirements.txt").exists(), "纯标准库插件不得提供 requirements.txt"
    for path in ROOT.rglob("*"):
        if "vendor" in path.parts:
            continue
        assert not path.is_symlink(), f"源码树不允许 symlink：{path}"


# ---------- 纯/服务层可离线导入且不依赖 SDK ----------
def test_pure_modules_importable_and_sdk_free():
    sys.path.insert(0, str(ROOT))
    import _audit_core as audit_core  # noqa: PLC0415

    expected_funcs = (
        "parse_skill_md",
        "normalize_skill_name",
        "skill_audit_text",
        "audit_skill_files",
        "scan_archive_for_skills",
        "inspect_dsh_plugin",
    )
    for fn in expected_funcs:
        assert callable(getattr(audit_core, fn, None)), f"纯层缺少 {fn}"

    for rel in ("_audit_core.py", "_sources.py", "_store.py"):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert "import plugin" not in src, f"{rel} 不应直接依赖宿主 SDK"
        assert "from plugin" not in src, f"{rel} 不应直接依赖宿主 SDK"
