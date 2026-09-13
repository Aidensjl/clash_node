import yaml
from pathlib import Path

# 初版仅获取节点，但是没有处理name
# =========================
# 配置
# =========================

INPUT_FILE = "1.yml"
OUTPUT_FILE = "ooooo.yml"

# 只保留这两种协议
ALLOWED_TYPES = {"vmess", "ss"}

# Clash 内置策略，不属于具体节点
BUILTIN_PROXIES = {
    "DIRECT",
    "REJECT",
    "GLOBAL",
    "PASS",
}


# =========================
# 读取 YAML
# =========================

input_path = Path(INPUT_FILE)
output_path = Path(OUTPUT_FILE)

if not input_path.exists():
    raise FileNotFoundError(
        f"找不到输入文件：{INPUT_FILE}\n"
        f"请把 Python 脚本和 {INPUT_FILE} 放在同一个目录。"
    )

with input_path.open("r", encoding="utf-8") as f:
    config = yaml.safe_load(f)


if not isinstance(config, dict):
    raise ValueError("YAML 文件格式错误，最外层必须是字典。")


# =========================
# 提取 VMess / SS
# =========================

proxies = config.get("proxies", [])

if not isinstance(proxies, list):
    raise ValueError("配置文件中的 proxies 不是列表。")


kept_proxies = []

for proxy in proxies:
    if not isinstance(proxy, dict):
        continue

    proxy_type = proxy.get("type")

    if proxy_type in ALLOWED_TYPES:
        kept_proxies.append(proxy)


# =========================
# 获取保留节点名称
# =========================

kept_names = {
    proxy.get("name")
    for proxy in kept_proxies
    if proxy.get("name")
}


# =========================
# 清理 proxy-groups
# =========================

proxy_groups = config.get("proxy-groups", [])

if isinstance(proxy_groups, list):

    for group in proxy_groups:

        if not isinstance(group, dict):
            continue

        group_proxies = group.get("proxies")

        if not isinstance(group_proxies, list):
            continue

        new_proxy_list = []

        for name in group_proxies:

            # 保留真正存在的 VMess / SS 节点
            if name in kept_names:
                new_proxy_list.append(name)

            # 保留 Clash 内置策略
            elif name in BUILTIN_PROXIES:
                new_proxy_list.append(name)

        group["proxies"] = new_proxy_list


# =========================
# 替换 proxies
# =========================

config["proxies"] = kept_proxies


# =========================
# 输出 YAML
# =========================

with output_path.open("w", encoding="utf-8") as f:

    yaml.safe_dump(
        config,
        f,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )


# =========================
# 统计结果
# =========================

vmess_count = sum(
    1
    for proxy in kept_proxies
    if proxy.get("type") == "vmess"
)

ss_count = sum(
    1
    for proxy in kept_proxies
    if proxy.get("type") == "ss"
)


print("=" * 50)
print("处理完成")
print("=" * 50)

print(f"输入文件：{INPUT_FILE}")
print(f"输出文件：{OUTPUT_FILE}")
print()

print(f"原始节点数量：{len(proxies)}")
print(f"保留节点数量：{len(kept_proxies)}")
print(f"VMess：{vmess_count}")
print(f"SS：{ss_count}")

print()
print(f"最终文件：{output_path.absolute()}")
print("=" * 50)

