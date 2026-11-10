"""DSH 兼容层 —— 纯标准库审计/解析层（不依赖宿主 SDK，可离线单测）。

包含：
- SKILL.md YAML frontmatter 解析与名称规范化；
- 静态安全审计规则与目录/压缩包扫描；
- DSH 函数型插件（TS/apply(ctx)）包结构识别。

本模块禁止 import ``plugin.*``，以便脱离宿主运行 `pytest tests/test_dsh.py`。
"""
from __future__ import annotations

import json
import os
import re
import tarfile

# ---------- 常量 ----------
_FM_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)  # YAML frontmatter + 正文

# ---------- 技能静态安全审计规则（只读不执行，静态启发式） ----------
_AUDIT_SCRIPT_EXTS = {".py", ".sh", ".ps1", ".js", ".bat", ".cmd", ".rb", ".pl", ".lua"}
AUDIT_RULES = [
    (
        "exec_shell",
        "critical",
        "脚本直接执行系统命令",
        re.compile(
            r"(?i)\b(os\.system|os\.popen|Popen|eval\s*\(|exec\s*\(|os\.exec|"
            r"commands\.getoutput|Invoke-Expression|\bIEX\b|Start-Process)\b"
        ),
        "脚本包含直接执行系统命令/代码的调用，运行时会执行任意命令",
        False,
    ),
    (
        "download_exec",
        "critical",
        "下载内容并直接执行",
        re.compile(
            r"(?i)(curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)\s+[^\r\n]{0,160}"
            r"\|\s*(ba|pw)?sh\b|(curl|wget)\s+[^\r\n]{0,160}\s+-o\s+"
            r"[^\r\n]{0,60}\.(py|sh|ps1)\s*[;&]"
        ),
        "从网络下载内容后直接执行或保存为脚本，可能运行不可信代码",
        False,
    ),
    (
        "read_secret_file",
        "critical",
        "脚本读取敏感文件",
        re.compile(
            r"(?i)(\.ssh[/\\]|id_rsa|\.aws[/\\]|credentials\.(json|ini|txt)|\.env\b|"
            r"wallet|mnemonic|seed[-_ ]?phrase|私钥|助记词)"
        ),
        "脚本可能读取 SSH 私钥/AWS 凭证/.env 等敏感文件",
        True,
    ),
    (
        "exfil",
        "high",
        "数据外传",
        re.compile(
            r"(?i)(发送|上传|提交|传回|外传|post|upload)[^\r\n]{0,60}"
            r"(到|至|给|to)[^\r\n]{0,90}(http|服务器|server|邮箱|api|接口|url|endpoint)"
        ),
        "可能把本地数据（聊天记录/文件/密码等）发送到外部",
        False,
    ),
    (
        "prompt_inject",
        "high",
        "提示注入特征",
        re.compile(
            r"(?i)(ignore\s+(previous|prior|above|earlier)\s+(instructions|prompts|rules)|"
            r"忽略[^\r\n]{0,24}(之前|以上|先前)[^\r\n]{0,12}(指令|提示|规则)|"
            r"disregard\s+(previous|prior|above)|you\s+are\s+now\s+(free|unconstrained|"
            r"a\s+new)|输出你的[^\r\n]{0,30}(系统|system)[^\r\n]{0,20}(提示|指令|prompt))"
        ),
        "存在试图操纵 AI 行为或套取系统提示词的文本，安装前请谨慎",
        False,
    ),
    (
        "ask_secret",
        "high",
        "要求用户提供敏感信息",
        re.compile(
            r"(?i)(请|麻烦|需要|让我|please)[^\r\n]{0,30}(输入|提供|告诉我|发给我|给我|给我发)"
            r"[^\r\n]{0,50}(密码|验证码|token|api[_-]?key|密钥|私钥|银行卡|支付|口令|账号密码)"
        ),
        "要求用户提供敏感信息，可能是钓鱼/社工",
        False,
    ),
    (
        "net_in_script",
        "medium",
        "脚本含网络访问",
        re.compile(
            r"(?i)\b(requests\.|urllib|http\.client|socket\.|urlopen|httpx|aiohttp|curl|wget|"
            r"Invoke-WebRequest|Invoke-RestMethod|ftp\.|smtplib)\b"
        ),
        "脚本含网络访问，运行时会外联，请确认目标地址可信",
        True,
    ),
    (
        "subprocess_use",
        "medium",
        "脚本使用 subprocess",
        re.compile(r"(?i)\bsubprocess\b|os\.system|os\.popen|Popen"),
        "脚本会调用系统命令，请确认命令参数可信",
        True,
    ),
    (
        "suspicious_link",
        "low",
        "可疑外部链接",
        re.compile(
            r"(?i)https?://[^\s\"'<>\)]+\.(zip|exe|msi|scr|bat|ps1)\b|"
            r"\b(bit\.ly|t\.cn|goo\.gl|tinyurl\.com|is\.gd)\b"
        ),
        "存在指向可执行/压缩包下载或短链的链接，需人工确认",
        False,
    ),
]
_AUDIT_LEVEL_ORDER = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------- frontmatter 解析 ----------
def parse_skill_md(text: str) -> dict:
    """解析 DSH SKILL.md：YAML frontmatter（name/description/whenToUse/description_zh 等）+ 正文。

    返回 {"name", "description", "when_to_use", "frontmatter", "body"}；
    无 frontmatter 或缺少 name/description 时 name/description 置空，由调用方决定。
    """
    m = _FM_RE.match(text.strip())
    if not m:
        return {"name": "", "description": "", "when_to_use": "", "frontmatter": {}, "body": text.strip()}
    fm_raw, body = m.group(1), m.group(2).strip()
    fm: dict = {}
    for line in fm_raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            fm[k.strip()] = v.strip().strip('"').strip("'")
    name = str(fm.get("name") or "").strip()
    desc = str(fm.get("description") or "").strip()
    when = str(fm.get("whenToUse") or fm.get("when_to_use") or "").strip()
    if not desc and fm.get("description_zh"):
        desc = str(fm["description_zh"]).strip()
    if not when and fm.get("whenToUse_zh"):
        when = str(fm["whenToUse_zh"]).strip()
    return {"name": name, "description": desc, "when_to_use": when, "frontmatter": fm, "body": body}


def normalize_skill_name(name: str) -> str:
    """DSH 名称规范化：kebab-case（大写转小写、下划线转连字符、非法字符去连）。"""
    n = name.strip().lower()
    n = re.sub(r"[_\s]+", "-", n)
    n = re.sub(r"[^a-z0-9-]+", "-", n)
    n = re.sub(r"-{2,}", "-", n).strip("-")
    return n or "unnamed-skill"


# ---------- 静态审计 ----------
def skill_audit_text(text: str, is_script: bool = False) -> list[dict]:
    """对技能文本/脚本做静态审计，返回命中规则列表。"""
    hits = []
    for rule_id, level, label, rx, hint, only_scripts in AUDIT_RULES:
        if only_scripts and not is_script:
            continue
        if rx.search(text):
            hits.append({"rule": rule_id, "level": level, "label": label, "hint": hint})
    return hits


def audit_skill_files(root: str) -> dict:
    """审计技能目录：SKILL.md 正文 + 全部脚本文件。返回最高级别与命中列表。"""
    findings = []
    top = "safe"
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(p)
                if size > 1_000_000:
                    continue
                ext = os.path.splitext(fn)[1].lower()
                with open(p, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            is_script = ext in _AUDIT_SCRIPT_EXTS
            if fn.lower() == "skill.md":
                is_script = False
            for hit in skill_audit_text(content, is_script=is_script):
                hit["file"] = os.path.relpath(p, root)
                findings.append(hit)
    for hit in findings:
        if _AUDIT_LEVEL_ORDER.get(hit["level"], 0) > _AUDIT_LEVEL_ORDER.get(top, 0):
            top = hit["level"]
    return {"level": top, "findings": findings}


# ---------- 包内技能扫描 ----------
def scan_archive_for_skills(tarball: str, want_name: str = "") -> list[dict]:
    """扫描 tar.gz 包内的 DSH 技能：<name>/SKILL.md 或 <name>.md（扁平）。

    返回 [{"name", "description", "when_to_use", "path", "body", "flat"}]；
    want_name 非空时只返回该技能。
    """
    found = []
    with tarfile.open(tarball, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            base = os.path.basename(member.name).lower()
            if base == "skill.md":
                dirname = os.path.basename(os.path.dirname(member.name))
                name = normalize_skill_name(dirname) if dirname and dirname not in (".", "skills") else ""
                f = tf.extractfile(member)
                text = f.read().decode("utf-8", errors="ignore") if f else ""
                parsed = parse_skill_md(text)
                nm = parsed["name"] or name or ""
                if not nm:
                    continue
                if want_name and normalize_skill_name(want_name) != nm:
                    continue
                found.append({
                    "name": nm,
                    "description": parsed["description"],
                    "when_to_use": parsed["when_to_use"],
                    "path": member.name,
                    "body": text,
                    "flat": False,
                })
            elif base.endswith(".md") and os.path.dirname(member.name).count("/") <= 1:
                # 扁平 <name>.md（仅浅层，排除深层文档；必须有 frontmatter name 才收录）
                f = tf.extractfile(member)
                text = f.read().decode("utf-8", errors="ignore") if f else ""
                parsed = parse_skill_md(text)
                if not parsed["name"]:
                    continue
                nm = parsed["name"]
                if want_name and normalize_skill_name(want_name) != nm:
                    continue
                found.append({
                    "name": nm,
                    "description": parsed["description"],
                    "when_to_use": parsed["when_to_use"],
                    "path": member.name,
                    "body": text,
                    "flat": True,
                })
    return found


# ---------- DSH 函数型插件包识别 ----------
def inspect_dsh_plugin(root: str) -> dict:
    """识别 DSH 函数型插件包：package.json / dsh.bundle / index.js / README。

    返回 {"is_dsh_plugin", "name", "version", "description", "entry", "bundle", "readme_snip"}。
    """
    pkg_path = os.path.join(root, "package.json")
    info = {"is_dsh_plugin": False, "name": "", "version": "", "description": "",
            "entry": "", "bundle": {}, "readme_snip": ""}
    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, encoding="utf-8", errors="ignore") as f:
                pkg = json.load(f)
            info["name"] = str(pkg.get("name") or "")
            info["version"] = str(pkg.get("version") or "")
            info["description"] = str(pkg.get("description") or "")
            if pkg.get("dsh") or pkg.get("dsh.bundle"):
                info["is_dsh_plugin"] = True
                dsh_cfg = pkg.get("dsh") or pkg.get("dsh.bundle") or {}
                info["bundle"] = dsh_cfg.get("bundle") or dsh_cfg
            if str(pkg.get("main") or "") and os.path.exists(os.path.join(root, str(pkg["main"]))):
                info["entry"] = str(pkg["main"])
        except (ValueError, OSError):
            pass
    if not info["bundle"] and os.path.exists(os.path.join(root, "dsh.bundle.yml")):
        info["is_dsh_plugin"] = True
    if not info["entry"]:
        for cand in ("index.js", "src/index.js", "dist/index.js"):
            if os.path.exists(os.path.join(root, cand)):
                info["entry"] = cand
                break
    for cand in ("README.md", "README.MD", "readme.md", "README"):
        p = os.path.join(root, cand)
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8", errors="ignore") as f:
                    info["readme_snip"] = f.read(800)
            except OSError:
                pass
            break
    return info
