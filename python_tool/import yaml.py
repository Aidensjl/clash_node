import yaml
from pathlib import Path

# 处理node+name,仅包含vmess和ss
# ============================================================
# 配置
# ============================================================

INPUT_FILE = "1.yml"
OUTPUT_FILE = "ooooo.yml"

# 只保留这些协议
ALLOWED_TYPES = {
    "vmess",
    "ss",
}


# ============================================================
# 读取原始 YAML
# ============================================================

input_path = Path(INPUT_FILE)
output_path = Path(OUTPUT_FILE)

if not input_path.exists():
    raise FileNotFoundError(
        f"找不到文件：{INPUT_FILE}"
    )

with input_path.open("r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

if not isinstance(config, dict):
    raise ValueError("YAML 格式错误")


# ============================================================
# 读取原始节点
# ============================================================

original_proxies = config.get("proxies", [])

if not isinstance(original_proxies, list):
    raise ValueError("proxies 必须是列表")


print(f"原始节点数量：{len(original_proxies)}")


# ============================================================
# 第一步：筛选 VMess / SS
# ============================================================

kept_proxies = []

for proxy in original_proxies:

    if not isinstance(proxy, dict):
        continue

    proxy_type = proxy.get("type")

    if proxy_type in ALLOWED_TYPES:
        kept_proxies.append(proxy)


# ============================================================
# 第二步：从筛选后的节点中获取名称
# ============================================================

kept_names = []

for proxy in kept_proxies:

    name = proxy.get("name")

    if name:
        kept_names.append(name)


# ============================================================
# 去除重复名称
# 保持原来的节点顺序
# ============================================================

kept_names = list(dict.fromkeys(kept_names))


# ============================================================
# 第三步：把筛选后的节点写入 proxies
# ============================================================

config["proxies"] = kept_proxies


# ============================================================
# 第四步：处理 proxy-groups
# ============================================================

proxy_groups = config.get("proxy-groups", [])

if not isinstance(proxy_groups, list):
    proxy_groups = []


# ------------------------------------------------------------
# 找到「节点选择」策略组
# ------------------------------------------------------------

node_select_group = None

for group in proxy_groups:

    if not isinstance(group, dict):
        continue

    if group.get("name") == "节点选择":
        node_select_group = group
        break


# ------------------------------------------------------------
# 如果原配置存在「节点选择」
# 就把它的 proxies 完全替换成筛选后的节点名称
# ------------------------------------------------------------

if node_select_group is not None:

    node_select_group["proxies"] = kept_names


# ------------------------------------------------------------
# 如果原配置没有「节点选择」
# 自动创建一个
# ------------------------------------------------------------

else:

    node_select_group = {
        "name": "节点选择",
        "type": "select",
        "proxies": kept_names,
    }

    proxy_groups.insert(0, node_select_group)


# ============================================================
# 第五步：处理其他 proxy-groups
# ============================================================

# 筛选后的节点名称集合
kept_name_set = set(kept_names)

# Clash 内置策略
builtin_names = {
    "DIRECT",
    "REJECT",
    "GLOBAL",
    "PASS",
}


for group in proxy_groups:

    if not isinstance(group, dict):
        continue

    # 「节点选择」已经在上面处理
    if group is node_select_group:
        continue

    group_proxies = group.get("proxies")

    if not isinstance(group_proxies, list):
        continue

    new_group_proxies = []

    for name in group_proxies:

        # 只保留：
        # 1. 筛选后真实存在的节点
        # 2. Clash 内置策略
        if name in kept_name_set:
            new_group_proxies.append(name)

        elif name in builtin_names:
            new_group_proxies.append(name)

    group["proxies"] = new_group_proxies


# ============================================================
# 把处理后的 proxy-groups 写回配置
# ============================================================

config["proxy-groups"] = proxy_groups


# ============================================================
# 第六步：生成最终 YAML
# ============================================================

with output_path.open("w", encoding="utf-8") as f:

    yaml.safe_dump(
        config,
        f,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )


# ============================================================
# 统计信息
# ============================================================

vmess_count = 0
ss_count = 0

for proxy in kept_proxies:

    if proxy.get("type") == "vmess":
        vmess_count += 1

    elif proxy.get("type") == "ss":
        ss_count += 1


print()
print("=" * 60)
print("处理完成")
print("=" * 60)

print(f"原始节点：{len(original_proxies)}")
print(f"筛选节点：{len(kept_proxies)}")
print(f"VMess：{vmess_count}")
print(f"SS：{ss_count}")
print(f"节点名称：{len(kept_names)}")

print()
print("最终节点名称：")

print()
print(f"输出文件：{output_path.absolute()}")

print("=" * 60)

