"""DSH 兼容层 —— 本地技能库文件层（仅标准库，不依赖宿主 SDK）。

负责技能库目录定位、列举、按名解析、安装落盘与可恢复卸载；
并发串行化、SDK 返回值组装由装配层 ``__init__.py`` 负责。
"""
from __future__ import annotations

import contextlib
import os
import shutil
import tarfile
import tempfile
import time

from ._audit_core import normalize_skill_name, scan_archive_for_skills

_MAX_ARCHIVE_ENTRIES = 5000


class StoreError(Exception):
    """技能库操作失败；装配层负责转换为宿主 SdkError。"""


def default_skills_dir() -> str:
    """返回（并按需创建）本插件技能库根目录。"""
    base = os.path.join(os.path.expandvars(r"%LOCALAPPDATA%"), "N.E.K.O", "dsh_compat")
    d = os.path.join(base, "skills")
    with contextlib.suppress(OSError):
        os.makedirs(d, exist_ok=True)
    return d


def list_skills() -> list[dict]:
    """扫描本插件技能库 + 只读的 ``~/.dsh/skills``，返回技能元信息列表。"""
    roots = [default_skills_dir()]
    dsh_home = os.path.join(os.path.expanduser("~"), ".dsh", "skills")
    if os.path.isdir(dsh_home):
        roots.append(dsh_home)
    out: list[dict] = []
    seen: set[str] = set()
    # 目录型：<name>/SKILL.md
    for root in roots:
        try:
            entries = list(os.scandir(root))
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir():
                continue
            name = normalize_skill_name(entry.name)
            if name in seen:
                continue
            md = os.path.join(entry.path, "SKILL.md")
            if not os.path.exists(md):
                continue
            try:
                with open(md, encoding="utf-8", errors="ignore") as f:
                    text = f.read(64 * 1024)
            except OSError:
                continue
            from ._audit_core import parse_skill_md

            parsed = parse_skill_md(text)
            seen.add(name)
            out.append({
                "name": parsed["name"] or name,
                "description": parsed["description"],
                "when_to_use": parsed["when_to_use"],
                "path": entry.path,
                "source": "dsh_compat" if root == roots[0] else "dsh_home",
            })
    # 扁平型：<name>.md
    for root in roots:
        try:
            entries = list(os.scandir(root))
        except OSError:
            continue
        for entry in entries:
            if not (entry.is_file() and entry.name.endswith(".md")):
                continue
            name = normalize_skill_name(os.path.splitext(entry.name)[0])
            if name in seen:
                continue
            try:
                with open(entry.path, encoding="utf-8", errors="ignore") as f:
                    text = f.read(64 * 1024)
            except OSError:
                continue
            from ._audit_core import parse_skill_md

            parsed = parse_skill_md(text)
            if not parsed["name"]:
                continue
            seen.add(name)
            out.append({
                "name": parsed["name"],
                "description": parsed["description"],
                "when_to_use": parsed["when_to_use"],
                "path": entry.path,
                "source": "dsh_compat" if root == roots[0] else "dsh_home",
            })
    out.sort(key=lambda x: x["name"])
    return out


def resolve_skill(name: str) -> str:
    """按名称（规范化）定位技能 SKILL.md 文件路径，找不到抛 StoreError。

    目录型技能的 ``path`` 是其目录，这里规范化到目录下的 ``SKILL.md``；
    扁平型技能 ``path`` 即 ``.md`` 文件本身。
    """
    want = normalize_skill_name(name)
    for it in list_skills():
        if normalize_skill_name(it["name"]) == want:
            p = it["path"]
            if os.path.isdir(p):
                p = os.path.join(p, "SKILL.md")
            return p
    raise StoreError(f"技能 '{name}' 未安装。先 dsh_list 看有哪些，或用 dsh_install 安装后再加载。")


def install_skill_items(skills_dir: str, data: bytes, want_name: str = "") -> list[dict]:
    """解包 tarball 字节流 → 扫描技能 → 落盘到技能库。返回安装清单。"""
    installed = []
    with tempfile.NamedTemporaryFile(suffix=".tgz", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        with tarfile.open(tmp_path, "r:gz") as tf:
            if len(tf.getmembers()) > _MAX_ARCHIVE_ENTRIES:
                raise StoreError("压缩包条目数超限（>5000），已中止")
            found = scan_archive_for_skills(tmp_path, want_name=want_name)
            if not found:
                if not want_name:
                    raise StoreError(
                        "包内未找到 DSH 技能（SKILL.md 需含 YAML frontmatter：name/description）。"
                        "确认该仓库/npm 包确实是 DSH 技能包，或指定 skill_name 精确安装。"
                    )
                raise StoreError(
                    f"包内未找到技能 '{want_name}'。先不带 skill_name 安装，查看包内全部技能名。"
                )
            for item in found:
                dest_dir = os.path.join(skills_dir, normalize_skill_name(item["name"]))
                os.makedirs(dest_dir, exist_ok=True)
                if item["flat"]:
                    # 扁平 <name>.md → 落 SKILL.md
                    with open(os.path.join(dest_dir, "SKILL.md"), "w", encoding="utf-8") as f:
                        f.write(item["body"])
                else:
                    # 目录型：把该技能目录内容复制过去
                    member_dir = os.path.dirname(item["path"])
                    for member in tf.getmembers():
                        if member.name == member_dir or not member.name.startswith(member_dir + "/"):
                            continue
                        rel = os.path.relpath(member.name, member_dir)
                        target = os.path.join(dest_dir, rel)
                        if member.isdir():
                            os.makedirs(target, exist_ok=True)
                        elif member.isfile():
                            os.makedirs(os.path.dirname(target), exist_ok=True)
                            src_f = tf.extractfile(member)
                            if src_f:
                                with open(target, "wb") as out:
                                    out.write(src_f.read())
                installed.append({
                    "name": item["name"],
                    "description": item["description"],
                    "path": dest_dir,
                })
    except (tarfile.TarError, OSError) as e:
        raise StoreError(f"解包失败：{e}") from None
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
    return installed


def move_to_trash(skills_dir: str, name: str) -> dict:
    """把本库中的技能移入 ``.trash-<时间戳>-<名称>``；找不到抛 StoreError。"""
    want = normalize_skill_name(name)
    target = os.path.join(skills_dir, want)
    if not os.path.exists(target):
        # 扁平匹配
        try:
            entries = list(os.scandir(skills_dir))
        except OSError:
            entries = []
        for entry in entries:
            if entry.is_file() and entry.name.endswith(".md") and \
                    normalize_skill_name(os.path.splitext(entry.name)[0]) == want:
                target = entry.path
                break
        if not os.path.exists(target):
            raise StoreError(
                f"技能 '{name}' 不在本插件技能库中。dsh_list 查看；~/.dsh/skills 的技能请到 DSH 侧管理。"
            )
    trash = os.path.join(skills_dir, f".trash-{int(time.time())}-{want}")
    shutil.move(target, trash)
    return {"uninstalled": want, "trash": trash, "target": target}
