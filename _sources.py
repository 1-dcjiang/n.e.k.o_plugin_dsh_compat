"""DSH 兼容层 —— 网络/包源层（仅标准库，不依赖宿主 SDK，便于离线测试 URL 与白名单）。

仅允许 GitHub（api.github.com / codeload.github.com）与 npm（registry.npmjs.org）
官方域名，其余来源在 `http_get` 处拒绝。
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request

_MAX_PACKAGE_BYTES = 200 * 1024 * 1024
_NPM_REGISTRY = "https://registry.npmjs.org"
_ALLOWED_HOSTS = ("api.github.com", "codeload.github.com", "registry.npmjs.org")


class SourceFetchError(Exception):
    """包源构造/下载失败；装配层负责转换为宿主 SdkError。"""


def http_get(url: str, timeout: int = 30, max_bytes: int = _MAX_PACKAGE_BYTES) -> bytes:
    """下载 URL 内容；强制 https 与官方白名单，超过 max_bytes 即中止。"""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS:
        raise SourceFetchError(f"拒绝非白名单下载源：{parsed.hostname}（仅允许 GitHub / npm 官方域名）")
    req = urllib.request.Request(url, headers={"User-Agent": "neko-dsh-compat/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SourceFetchError("下载包超过大小上限（200MB），已中止")
    return data


def build_github_tarball_url(repo_ref: str) -> str:
    """把 ``owner/repo`` 或 ``owner/repo#ref`` 转成 codeload tarball 地址。"""
    repo_ref = repo_ref.strip()
    ref = ""
    if "#" in repo_ref:
        repo_ref, ref = repo_ref.split("#", 1)
    repo_ref = repo_ref.strip("/")
    parts = repo_ref.split("/")
    if len(parts) < 2:
        raise SourceFetchError(f"GitHub 仓库格式应为 owner/repo（收到：{repo_ref}）")
    owner, repo = parts[0], parts[1]
    if not re.match(r"^[A-Za-z0-9-]+$", owner) or not re.match(r"^[A-Za-z0-9._-]+$", repo):
        raise SourceFetchError("GitHub 仓库名含非法字符")
    if ref:
        return f"https://codeload.github.com/{owner}/{repo}/tar.gz/{urllib.parse.quote(ref)}"
    return f"https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"


def build_npm_tarball_url(pkg: str, fetch_json=None) -> str:
    """根据 npm 包名取 tarball 地址；``fetch_json`` 可注入离线元数据查询便于单测。"""
    pkg = pkg.strip()
    if pkg.startswith("@"):
        if pkg.count("/") != 1:
            raise SourceFetchError(f"npm 包名格式应为 @scope/name（收到：{pkg}）")
    elif "/" in pkg:
        raise SourceFetchError(f"npm 包名不应含 '/'（收到：{pkg}）")
    if fetch_json is None:
        fetch_json = lambda name: json.loads(
            http_get(f"{_NPM_REGISTRY}/{urllib.parse.quote(name)}", timeout=30, max_bytes=2_000_000)
            .decode("utf-8")
        )
    try:
        meta = fetch_json(pkg)
    except (SourceFetchError, ValueError, OSError) as e:
        raise SourceFetchError(f"查询 npm 包失败：{e}") from None
    tarball = (meta.get("dist") or {}).get("tarball") or ""
    if not tarball or "registry.npmjs.org" not in tarball:
        raise SourceFetchError("npm 包缺少可用 tarball 地址")
    return tarball
