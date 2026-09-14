#!/usr/bin/env python3
"""
merge_yaml.py — 合并目录下所有 .yaml/.yml 的 proxies，并统一重命名为 node_1..node_x

用法:
    python python_tool/merge_yaml.py MyNode -o MyNode/merged.yml --exclude merged.yml
"""

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml


def load_proxies(path: Path) -> List[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"::warning::YAML 解析失败 {path}: {e}")
        return []
    except OSError as e:
        print(f"::warning::读取失败 {path}: {e}")
        return []

    if isinstance(data, dict):
        p = data.get("proxies")
        return p if isinstance(p, list) else []
    if isinstance(data, list):
        return data
    return []


def rename_sequential(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """按顺序重命名为 node_1..node_x，并按 (type,server,port,password) 去重。"""
    seen_keys = set()
    out: List[Dict[str, Any]] = []
    idx = 1

    for n in nodes:
        key = (n.get("type"), n.get("server"), n.get("port"), n.get("password"))
        if key in seen_keys:
            continue
        seen_keys.add(key)

        n = dict(n)                 # 浅拷贝，避免改到调用方
        n["name"] = f"node_{idx}"
        idx += 1
        out.append(n)

    return out


def collect_yaml_files(in_dir: Path, output_path: Path, exclude_names: set) -> List[Path]:
    result = []
    seen = set()
    for pattern in ("*.yaml", "*.yml", "*.YAML", "*.YML"):
        for p in in_dir.glob(pattern):
            rp = p.resolve()
            if rp == output_path or p.name in exclude_names or rp in seen:
                continue
            seen.add(rp)
            result.append(p)
    return sorted(result)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input_dir")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--exclude", nargs="*", default=[])
    args = ap.parse_args()

    in_dir = Path(args.input_dir)
    if not in_dir.is_dir():
        print(f"::error::目录不存在: {in_dir}")
        return 1

    output_path = Path(args.output).resolve()
    exclude = set(args.exclude)

    yaml_files = collect_yaml_files(in_dir, output_path, exclude)

    if not yaml_files:
        print(f"::warning::{in_dir} 下没有 .yaml / .yml 文件")
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text("proxies: []\n", encoding="utf-8")
        return 0

    print(f"发现 {len(yaml_files)} 个 YAML 文件:")
    for f in yaml_files:
        print(f"  - {f.name}")

    all_nodes: List[Dict[str, Any]] = []
    for f in yaml_files:
        nodes = load_proxies(f)
        print(f"  {f.name}: {len(nodes)} 个节点")
        all_nodes.extend(nodes)

    before = len(all_nodes)
    all_nodes = rename_sequential(all_nodes)
    print(f"去重+重命名: {before} → {len(all_nodes)}  (node_1..node_{len(all_nodes)})")

    # 二次校验：name 必须唯一
    names = [n["name"] for n in all_nodes]
    if len(names) != len(set(names)):
        print("::error::重命名后仍有重复，逻辑有 bug")
        return 1

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fp:
        yaml.dump(
            {"proxies": all_nodes},
            fp,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
            indent=2,
            width=4096,
        )

    print(f"✅ 写入 {args.output}，共 {len(all_nodes)} 个节点")
    return 0


if __name__ == "__main__":
    sys.exit(main())