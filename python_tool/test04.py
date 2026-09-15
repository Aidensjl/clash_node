#!/usr/bin/env python3
"""
fix_clash.py — Clash 配置一键修复

修复内容：
  1. 重名节点           → 自动加 " #2"、" #3" 后缀
  2. http-opts          → path / headers.* 统一为数组
  3. h2-opts            → host 为数组，path 为字符串
  4. ws-opts            → path / headers.* 统一为字符串
  5. grpc-opts          → grpc-service-name 为字符串
  6. hysteria2          → 误用的 fingerprint 改为 client-fingerprint
  7. hysteria2          → obfs / obfs-password 一致性
  8. ss                 → cipher: auto 改为 aes-256-gcm
  9. 自动校验           → 确保所有字段合规

用法:
    python fix_clash.py input.yml output.yml
    python fix_clash.py input.yml            # 生成 input.fixed.yml
"""

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import yaml


# ============================================================
#  常量
# ============================================================

VALID_SS_CIPHERS = {
    "none", "dummy",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5",
    "chacha20-ietf", "xchacha20",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}

DEFAULT_SS_CIPHER = "aes-256-gcm"


# ============================================================
#  工具函数
# ============================================================

def to_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def to_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return v[0] if v else ""
    return str(v)


def is_hex_sha256(s: Any) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)


# ============================================================
#  修复函数
# ============================================================

def fix_opts_types(node: Dict[str, Any]) -> bool:
    """http-opts / h2-opts / ws-opts / grpc-opts 字段类型规范化。"""
    changed = False

    # http-opts: path / headers.* 必须是数组
    http_opts = node.get("http-opts")
    if isinstance(http_opts, dict):
        if "path" in http_opts and not isinstance(http_opts["path"], list):
            http_opts["path"] = to_list(http_opts["path"])
            changed = True
        headers = http_opts.get("headers")
        if isinstance(headers, dict):
            for k in list(headers):
                if not isinstance(headers[k], list):
                    headers[k] = to_list(headers[k])
                    changed = True

    # h2-opts: host 数组，path 字符串
    h2_opts = node.get("h2-opts")
    if isinstance(h2_opts, dict):
        if "host" in h2_opts and not isinstance(h2_opts["host"], list):
            h2_opts["host"] = to_list(h2_opts["host"])
            changed = True
        if "path" in h2_opts and isinstance(h2_opts["path"], list):
            h2_opts["path"] = to_str(h2_opts["path"])
            changed = True
        headers = h2_opts.get("headers")
        if isinstance(headers, dict):
            for k in list(headers):
                if not isinstance(headers[k], list):
                    headers[k] = to_list(headers[k])
                    changed = True

    # ws-opts: path / headers.* 必须是字符串
    ws_opts = node.get("ws-opts")
    if isinstance(ws_opts, dict):
        if "path" in ws_opts and isinstance(ws_opts["path"], list):
            ws_opts["path"] = to_str(ws_opts["path"])
            changed = True
        headers = ws_opts.get("headers")
        if isinstance(headers, dict):
            for k in list(headers):
                if isinstance(headers[k], list):
                    headers[k] = to_str(headers[k])
                    changed = True

    # grpc-opts: grpc-service-name 字符串
    grpc_opts = node.get("grpc-opts")
    if isinstance(grpc_opts, dict) and "grpc-service-name" in grpc_opts:
        if isinstance(grpc_opts["grpc-service-name"], list):
            grpc_opts["grpc-service-name"] = to_str(grpc_opts["grpc-service-name"])
            changed = True

    return changed


def fix_fingerprint(node: Dict[str, Any]) -> bool:
    """hysteria2 误用的 fingerprint 改为 client-fingerprint。"""
    if node.get("type") != "hysteria2":
        return False
    fp = node.get("fingerprint")
    if fp is None:
        return False
    if is_hex_sha256(fp):
        return False
    if "client-fingerprint" not in node:
        node["client-fingerprint"] = fp
    del node["fingerprint"]
    return True


def fix_obfs(node: Dict[str, Any]) -> bool:
    """hysteria2 obfs / obfs-password 一致性。"""
    if node.get("type") != "hysteria2":
        return False

    obfs = node.get("obfs")
    pwd = node.get("obfs-password")

    has_obfs = obfs is not None and obfs != ""
    has_pwd = pwd is not None and pwd != ""

    if has_obfs and not has_pwd:
        del node["obfs"]
        node.pop("obfs-password", None)
        return True

    if has_pwd and not has_obfs:
        del node["obfs-password"]
        return True

    if not has_obfs and not has_pwd:
        changed = False
        if "obfs" in node:
            del node["obfs"]
            changed = True
        if "obfs-password" in node:
            del node["obfs-password"]
            changed = True
        return changed

    return False


def fix_ss_cipher(node: Dict[str, Any]) -> bool:
    """ss cipher 为 auto / 缺失 / 非法 → 改为 aes-256-gcm。"""
    if node.get("type") != "ss":
        return False

    cipher = node.get("cipher")

    if cipher is None or cipher == "":
        node["cipher"] = DEFAULT_SS_CIPHER
        return True

    if cipher == "auto" or cipher not in VALID_SS_CIPHERS:
        node["cipher"] = DEFAULT_SS_CIPHER
        return True

    return False


def fix_duplicate_names(proxies: List[Dict[str, Any]]) -> int:
    """重名节点加 " #N" 后缀。"""
    name_count: Dict[str, int] = {}
    renamed = 0

    for node in proxies:
        name = (node.get("name") or "").strip() or "node"

        if name not in name_count:
            name_count[name] = 1
            continue

        idx = name_count[name] + 1
        new_name = f"{name} #{idx}"
        while new_name in name_count:
            idx += 1
            new_name = f"{name} #{idx}"
        name_count[name] = idx
        name_count[new_name] = 1
        node["name"] = new_name
        renamed += 1

    return renamed


# ============================================================
#  主流程
# ============================================================

def process_file(src: Path, dst: Path) -> int:
    with src.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        print("::error::顶层不是 dict")
        return 1

    proxies = data.get("proxies")
    if not isinstance(proxies, list):
        print("::error::没有 proxies 列表")
        return 1

    total = len(proxies)
    print(f"📥 读取 {total} 个节点")

    # 统计原始重名
    names = [n.get("name") for n in proxies if isinstance(n, dict)]
    dup = {k: v for k, v in Counter(names).items() if v > 1}
    if dup:
        print(f"🔍 发现 {len(dup)} 个重名（共 {sum(dup.values())} 个节点）")
        for name, cnt in sorted(dup.items(), key=lambda x: -x[1])[:10]:
            print(f"    {name!r}: {cnt} 次")
        if len(dup) > 10:
            print(f"    ... 还有 {len(dup) - 10} 个")

    # 应用修复
    fix_opts = 0
    fix_fp = 0
    fix_obfs_cnt = 0
    fix_ss = 0

    for node in proxies:
        if not isinstance(node, dict):
            continue
        if fix_opts_types(node):
            fix_opts += 1
        if fix_fingerprint(node):
            fix_fp += 1
        if fix_obfs(node):
            fix_obfs_cnt += 1
        if fix_ss_cipher(node):
            fix_ss += 1

    fix_dup = fix_duplicate_names(proxies)

    print(f"🔧 http-opts/ws-opts/h2-opts/grpc-opts 类型修复: {fix_opts}")
    print(f"🔧 hysteria2 fingerprint 修复: {fix_fp}")
    print(f"🔧 hysteria2 obfs 一致性修复: {fix_obfs_cnt}")
    print(f"🔧 ss cipher 规范化: {fix_ss}")
    print(f"🔧 重名节点重命名: {fix_dup}")

    # 校验
    errors = []

    final_names = [n.get("name") for n in proxies]
    if len(final_names) != len(set(final_names)):
        dup_after = [k for k, v in Counter(final_names).items() if v > 1]
        errors.append(f"仍有重名: {dup_after[:5]}")

    for i, node in enumerate(proxies):
        http = node.get("http-opts")
        if isinstance(http, dict):
            p = http.get("path")
            if p is not None and not isinstance(p, list):
                errors.append(f"node[{i}] {node.get('name')}: http-opts.path 不是数组")
            h = http.get("headers")
            if isinstance(h, dict):
                for k, v in h.items():
                    if not isinstance(v, list):
                        errors.append(f"node[{i}] {node.get('name')}: http-opts.headers.{k} 不是数组")

        ws = node.get("ws-opts")
        if isinstance(ws, dict):
            p = ws.get("path")
            if p is not None and not isinstance(p, str):
                errors.append(f"node[{i}] {node.get('name')}: ws-opts.path 不是字符串")

        h2 = node.get("h2-opts")
        if isinstance(h2, dict):
            h = h2.get("host")
            if h is not None and not isinstance(h, list):
                errors.append(f"node[{i}] {node.get('name')}: h2-opts.host 不是数组")

        t = node.get("type")
        if t == "hysteria2":
            fp = node.get("fingerprint")
            if fp is not None and not is_hex_sha256(fp):
                errors.append(f"node[{i}] {node.get('name')}: hysteria2 误用 fingerprint")
            obfs = node.get("obfs")
            pwd = node.get("obfs-password")
            has_obfs = obfs is not None and obfs != ""
            has_pwd = pwd is not None and pwd != ""
            if has_obfs != has_pwd:
                errors.append(f"node[{i}] {node.get('name')}: obfs/obfs-password 不一致")

        if t == "ss":
            c = node.get("cipher")
            if c not in VALID_SS_CIPHERS:
                errors.append(f"node[{i}] {node.get('name')}: ss cipher 非法: {c!r}")

    if errors:
        print(f"❌ 校验失败，发现 {len(errors)} 个问题:")
        for e in errors[:10]:
            print(f"    {e}")
        if len(errors) > 10:
            print(f"    ... 还有 {len(errors) - 10} 个")
        return 1

    print("✅ 校验通过：所有字段合规")

    with dst.open("w", encoding="utf-8") as f:
        yaml.dump(
            data,
            f,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
            indent=2,
            width=4096,
        )

    print(f"💾 写入 {dst}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Clash 配置一键修复")
    ap.add_argument("input", help="输入 YAML 文件")
    ap.add_argument("output", nargs="?", help="输出文件（不填则生成 <input>.fixed.yml）")
    args = ap.parse_args()

    src = Path(args.input)
    if not src.is_file():
        print(f"::error::文件不存在: {src}")
        return 1

    dst = Path(args.output) if args.output else src.with_suffix(".fixed.yml")
    return process_file(src, dst)


if __name__ == "__main__":
    sys.exit(main())