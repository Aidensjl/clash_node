# SPDX-License-Identifier: GPL-3.0
"""
能够将抓到的node转为clash格式
test.py to-clash /MyNode/kooker.jp.txt -o my.yml

订阅链接 ↔ Clash 配置 双向转换器（Python 移植版）

原版：https://github.com/siiway/urlclash-converter/blob/main/src/converter.ts
基于：https://github.com/clash-verge-rev/clash-verge-rev/blob/dev/src/utils/uri-parser.ts

本工具仅提供 URL 和 Clash Config 的配置文件格式转换，不存储任何信息，
不提供任何代理服务，一切使用产生后果由使用者自行承担。
"""

import base64
import binascii
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote, unquote, urlencode, parse_qsl

try:
    import yaml
except ImportError:
    yaml = None


# ============================================================
#  工具函数
# ============================================================

def punycode_domain(domain: str) -> str:
    """国际化域名转 punycode（IPv4/IPv6 原样返回）。"""
    if not domain:
        return domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) or ":" in domain:
        return domain
    try:
        return domain.encode("idna").decode("ascii")
    except Exception:
        return domain


def get_if_not_blank(value, dft=None):
    if not value:
        return dft
    if isinstance(value, str) and not value.strip():
        return dft
    return value


def get_if_present(value, dft=None):
    return value if value else dft


def is_present(value) -> bool:
    return value is not None


def trim_str(s):
    if s is None:
        return None
    return s.strip() if s else s


def is_ipv4(address: str) -> bool:
    return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", address))


def is_ipv6(address: str) -> bool:
    """仅用于 WireGuard 地址分类（调用前已先判 is_ipv4）。"""
    if ":" not in address:
        return False
    dcolon = address.count("::")
    if dcolon > 1:
        return False
    parts = address.split(":")
    if len(parts) < 3 or len(parts) > 8:
        return False
    empty_count = sum(1 for p in parts if p == "")
    if dcolon == 0 and empty_count > 0:
        return False
    if dcolon == 1:
        expect = 2 if (address.startswith("::") or address.endswith("::")) else 1
        if empty_count != expect:
            return False
    return all(p == "" or re.match(r"^[0-9a-fA-F]{1,4}$", p) for p in parts)


def _pad_b64(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def decode_base64_or_original(s: str) -> str:
    """解码 base64；失败则原样返回。优先 UTF-8，失败退回 latin-1。"""
    if not s:
        return s
    try:
        cleaned = _pad_b64(re.sub(r"\s+", "", s))
        raw = base64.b64decode(cleaned, validate=False)
    except (binascii.Error, ValueError):
        return s
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def decode_base64_strict(s: str) -> Optional[str]:
    if not s:
        return None
    try:
        raw = base64.b64decode(_pad_b64(s), validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def utf8_to_base64(s: str) -> str:
    """UTF-8 安全 base64（Python 无需像 JS 那样绕 Latin-1）。"""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def get_cipher(s: Optional[str]) -> str:
    table = {
        "none": "none", "auto": "auto", "dummy": "dummy",
        "aes-128-gcm": "aes-128-gcm",
        "aes-192-gcm": "aes-192-gcm",
        "aes-256-gcm": "aes-256-gcm",
        "chacha20-ietf-poly1305": "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305": "xchacha20-ietf-poly1305",
    }
    return table.get(s or "", "auto")


def parse_query(qs: str) -> Dict[str, str]:
    if not qs:
        return {}
    return dict(parse_qsl(qs, keep_blank_values=True))


def _truthy(v) -> bool:
    """模拟 JS 的 /^(TRUE|1)$/i 判断。"""
    if v is True:
        return True
    return bool(re.match(r"^(TRUE|1)$", str(v), re.I)) if v is not None else False


# ============================================================
#  URI → 节点对象
# ============================================================

def parse_uri(uri: str) -> Optional[Dict[str, Any]]:
    head = uri.split("://", 1)[0].lower() if "://" in uri else uri.lower()
    mapping = {
        "ss": uri_ss, "ssr": uri_ssr, "vmess": uri_vmess, "vless": uri_vless,
        "trojan": uri_trojan, "anytls": uri_anytls,
        "hysteria2": uri_hysteria2, "hy2": uri_hysteria2,
        "hysteria": uri_hysteria, "hy": uri_hysteria,
        "tuic": uri_tuic,
        "wireguard": uri_wireguard, "wg": uri_wireguard,
        "http": uri_http, "socks5": uri_socks,
    }
    fn = mapping.get(head)
    if not fn:
        raise ValueError(f"Unknown uri type: {head}")
    return fn(uri)


def uri_ss(line: str) -> Dict[str, Any]:
    body = line.split("ss://", 1)[1]
    hash_idx = line.find("#")
    name = unquote(line[hash_idx + 1:]).strip() if hash_idx != -1 else ""
    proxy: Dict[str, Any] = {"name": name, "type": "ss", "server": "", "port": 0}

    content = body.split("#", 1)[0]
    m = re.search(r"@([^/]*)(/|$)", content)
    user_info = decode_base64_or_original(content.split("@", 1)[0])
    query = ""

    if not m:
        if "?" in content:
            pm = re.match(r"^(.*?)(\?.*)$", content)
            if pm:
                content, query = pm.group(1), pm.group(2)
        content = decode_base64_or_original(content)
        if query:
            if re.search(r"[&?]v2ray-plugin=", query):
                pm = re.search(r"[&?]v2ray-plugin=(.*?)(&|$)", query)
                if pm and pm.group(1):
                    proxy["plugin"] = "v2ray-plugin"
                    try:
                        proxy["plugin-opts"] = json.loads(decode_base64_or_original(pm.group(1)))
                    except (json.JSONDecodeError, ValueError):
                        pass
            content = content + query
        user_info = content.split("@", 1)[0]
        m = re.search(r"@([^/]*)(/|$)", content)

    server_and_port = m.group(1) if m else None
    if server_and_port:
        idx = server_and_port.rfind(":")
        if idx == -1:
            server, port_part = "", server_and_port
        else:
            server, port_part = server_and_port[:idx], server_and_port[idx + 1:]
    else:
        server, port_part = "", ""

    pm = re.search(r"\d+", port_part)
    proxy["server"] = server
    proxy["port"] = int(pm.group(0)) if pm else 0

    um = re.match(r"^(.*?):(.*)$", user_info)
    proxy["cipher"] = get_cipher(um.group(1) if um else None)
    proxy["password"] = um.group(2) if um else None

    if "?plugin=" in content:
        plugin_raw = content.split("?plugin=", 1)[1].split("&", 1)[0]
        plugin_info = ("plugin=" + unquote(plugin_raw)).split(";")
        params: Dict[str, Any] = {}
        for item in plugin_info:
            k, _, v = item.partition("=")
            if k:
                params[k] = v if v else True
        pname = params.get("plugin")
        if pname in ("obfs-local", "simple-obfs"):
            proxy["plugin"] = "obfs"
            proxy["plugin-opts"] = {
                "mode": params.get("obfs"),
                "host": get_if_not_blank(params.get("obfs-host")),
            }
        elif pname == "v2ray-plugin":
            proxy["plugin"] = "v2ray-plugin"
            proxy["plugin-opts"] = {
                "mode": "websocket",
                "host": get_if_not_blank(params.get("obfs-host")),
                "path": get_if_not_blank(params.get("path")),
                "tls": get_if_present(params.get("tls")),
            }
        else:
            raise ValueError(f"Unsupported plugin option: {pname}")

    if re.search(r"[&?]uot=(1|true)", query, re.I):
        proxy["udp-over-tcp"] = True
    if re.search(r"[&?]tfo=(1|true)", query, re.I):
        proxy["tfo"] = True
    if not proxy["name"]:
        proxy["name"] = f"SS {proxy['server']}:{proxy['port']}"
    return proxy


def uri_ssr(line: str) -> Dict[str, Any]:
    decoded = decode_base64_or_original(line.split("ssr://", 1)[1])
    split_idx = decoded.find(":origin")
    if split_idx == -1:
        split_idx = decoded.find(":auth_")
    server_and_port = decoded[:split_idx]
    last_colon = server_and_port.rfind(":")
    server = server_and_port[:last_colon]
    port = int(server_and_port[last_colon + 1:])

    parts = decoded[split_idx + 1:].split("/?")[0].split(":")
    proxy: Dict[str, Any] = {
        "name": "SSR", "type": "ssr", "server": server, "port": port,
        "protocol": parts[0],
        "cipher": get_cipher(parts[1] if len(parts) > 1 else None),
        "obfs": parts[2] if len(parts) > 2 else None,
        "password": decode_base64_or_original(parts[3] if len(parts) > 3 else ""),
    }

    other: Dict[str, str] = {}
    if "/?" in decoded:
        for item in decoded.split("/?", 1)[1].split("&"):
            k, _, v = item.partition("=")
            if v.strip():
                other[k] = v.strip()

    remarks = other.get("remarks")
    proxy["name"] = decode_base64_or_original(remarks).strip() if remarks else (proxy["server"] or "")
    pp = re.sub(r"\s", "", decode_base64_or_original(other.get("protoparam", "")))
    op = re.sub(r"\s", "", decode_base64_or_original(other.get("obfsparam", "")))
    proxy["protocol-param"] = get_if_not_blank(pp)
    proxy["obfs-param"] = get_if_not_blank(op)
    return proxy


def uri_vmess(line: str) -> Optional[Dict[str, Any]]:
    body = line.split("vmess://", 1)[1]
    hash_idx = body.find("#")
    if hash_idx != -1:
        fragment = unquote(body[hash_idx + 1:])
        body = body[:hash_idx]
    else:
        fragment = ""

    content = decode_base64_or_original(body)

    # ---- Quantumult 格式：xxx=vmess,...
    if re.search(r"=\s*vmess", content):
        partitions = [p.strip() for p in content.split(",")]
        params: Dict[str, str] = {}
        for part in partitions:
            if "=" in part:
                k, _, v = part.partition("=")
                params[k.strip()] = v.strip()

        proxy: Dict[str, Any] = {
            "name": partitions[0].split("=")[0].strip(),
            "type": "vmess",
            "server": partitions[1] if len(partitions) > 1 else "",
            "port": int(partitions[2]) if len(partitions) > 2 and partitions[2].isdigit() else 0,
            "cipher": get_cipher(get_if_not_blank(partitions[3] if len(partitions) > 3 else None, "auto")),
            "uuid": "",
            "tls": params.get("obfs") == "wss",
            "udp": get_if_present(params.get("udp-relay")),
            "tfo": get_if_present(params.get("fast-open")),
            "skip-cert-verify": (not params["tls-verification"]) if is_present(params.get("tls-verification")) else None,
        }
        uuid_val = partitions[4] if len(partitions) > 4 else ""
        um = re.match(r'^"(.*)"$', uuid_val)
        proxy["uuid"] = um.group(1) if um else ""

        if is_present(params.get("obfs")):
            if params["obfs"] in ("ws", "wss"):
                proxy["network"] = "ws"
                obfs_path = get_if_not_blank(params.get("obfs-path")) or '"/"'
                pm = re.match(r'^"(.*)"$', obfs_path)
                obfs_header = params.get("obfs-header") or ""
                hm = re.search(r"Host:\s*([a-zA-Z0-9\-.]*)", obfs_header)
                proxy["ws-opts"] = {
                    "path": pm.group(1) if pm else "/",
                    "headers": {"Host": hm.group(1) if hm else ""},
                }
            else:
                raise ValueError(f"Unsupported obfs: {params['obfs']}")
        return proxy

    # ---- V2rayN / Shadowrocket
    params = {}
    try:
        params = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        m = re.match(r"^([^?]+?)/?\?(.*)$", body)
        if m:
            base64_line, qs = m.group(1), m.group(2)
            content = decode_base64_or_original(base64_line)
            for addon in qs.split("&"):
                k, _, v = addon.partition("=")
                v = unquote(v)
                params[k] = v.split(",") if "," in v else v

            cm = re.match(r"^([^:]+?):([^:]+?)@(.*):(\d+)$", content)
            if cm:
                _, cipher, uuid, server, port = cm.groups()
                params["scy"] = cipher
                params["id"] = uuid
                params["port"] = port
                params["add"] = server

    server = params.get("add")
    try:
        port = int(get_if_present(params.get("port")))
    except (TypeError, ValueError):
        port = 0
    if not server or not port:
        return None

    name = (
        trim_str(params.get("ps"))
        or trim_str(params.get("remarks"))
        or trim_str(params.get("remark"))
        or trim_str(fragment)
        or f"VMess {server}:{port}"
    )

    tls_val = params.get("tls")
    proxy = {
        "name": name, "type": "vmess", "server": server, "port": port,
        "cipher": get_cipher(get_if_present(params.get("scy"), "auto")),
        "uuid": params.get("id"),
        "tls": tls_val in ("tls", "1") or tls_val is True or tls_val == 1,
        "skip-cert-verify": (not params["verify_cert"]) if is_present(params.get("verify_cert")) else None,
    }

    aid = params.get("aid") if params.get("aid") is not None else params.get("alterId")
    try:
        proxy["alterId"] = int(get_if_present(aid, 0))
    except (TypeError, ValueError):
        proxy["alterId"] = 0

    if proxy["tls"] and params.get("sni"):
        proxy["servername"] = params["sni"]

    httpupgrade = False
    net = params.get("net")
    obfs = params.get("obfs")
    typ = params.get("type")
    if net == "ws" or obfs == "websocket":
        proxy["network"] = "ws"
    elif net == "http" or obfs == "http" or typ == "http":
        proxy["network"] = "http"
    elif net == "grpc":
        proxy["network"] = "grpc"
    elif net == "httpupgrade":
        proxy["network"] = "ws"
        httpupgrade = True
    elif net == "h2" or proxy.get("network") == "h2":
        proxy["network"] = "h2"

    if proxy.get("network"):
        th = params.get("host") if params.get("host") is not None else params.get("obfsParam")
        try:
            if isinstance(th, str):
                parsed = json.loads(th)
                if isinstance(parsed, dict) and parsed.get("Host"):
                    th = parsed["Host"]
        except (json.JSONDecodeError, ValueError):
            pass

        tp = params.get("path")
        if proxy["network"] == "http":
            if isinstance(th, list):
                th = th[0] if th else None
            if tp:
                if isinstance(tp, list):
                    tp = tp[0] if tp else None
            else:
                tp = "/"

        if tp or th:
            if proxy["network"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": get_if_not_blank(tp)}
            else:
                opts = {
                    "path": get_if_not_blank(tp),
                    "headers": {"Host": get_if_not_blank(th)},
                }
                if httpupgrade:
                    opts["v2ray-http-upgrade"] = True
                    opts["v2ray-http-upgrade-fast-open"] = True
                n = proxy["network"]
                if n == "ws":
                    proxy["ws-opts"] = opts
                elif n == "http":
                    proxy["http-opts"] = opts
                elif n == "h2":
                    proxy["h2-opts"] = opts
        else:
            del proxy["network"]

        if proxy.get("tls") and not proxy.get("servername") and th:
            proxy["servername"] = th

    return proxy


def uri_vless(line: str) -> Dict[str, Any]:
    body = line.split("vless://", 1)[1]
    is_shadowrocket = False

    m = re.match(r"^(.*?)@(.*?):(\d+)/?(?:\?(.*?))?(?:#(.*?))?$", body)
    parsed = m.groups() if m else None

    if parsed is None:
        m2 = re.match(r"^([a-zA-Z0-9+/=]+)(\?.*?)?(#.*)?$", body)
        if m2:
            b64, q, h = m2.group(1), m2.group(2) or "", m2.group(3) or ""
            try:
                decoded = base64.b64decode(_pad_b64(b64)).decode("latin-1") + q + h
                body = decoded
                m3 = re.match(r"^(.*?)@(.*?):(\d+)/?(?:\?(.*?))?(?:#(.*?))?$", decoded)
                if m3:
                    parsed = m3.groups()
                    is_shadowrocket = True
            except Exception as e:
                print(f"Shadowrocket base64 decode failed: {e}")

    if parsed is None:
        raise ValueError("Invalid VLESS URI")

    uuid_raw, server_raw, port_str, addons, name_raw = (
        parsed[0], parsed[1], parsed[2], parsed[3] or "", parsed[4]
    )

    server = server_raw[1:-1] if server_raw.startswith("[") and server_raw.endswith("]") else server_raw
    uuid = uuid_raw
    if is_shadowrocket:
        uuid = re.sub(r"^.*?:", "", uuid, count=1)
    uuid = unquote(uuid)
    name = unquote(name_raw or "")
    port = int(port_str)

    proxy: Dict[str, Any] = {"type": "vless", "name": "", "server": server, "port": port, "uuid": uuid}

    params: Dict[str, str] = {}
    for addon in addons.split("&"):
        if not addon:
            continue
        k, _, v = addon.partition("=")
        params[k.lower()] = unquote(v)

    proxy["name"] = (
        trim_str(name)
        or trim_str(params.get("remarks"))
        or trim_str(params.get("remark"))
        or f"VLESS {server}:{port}"
    )

    security = params.get("security")
    proxy["tls"] = (bool(security) and security != "none") or None

    if is_shadowrocket and _truthy(params.get("tls", "")):
        proxy["tls"] = True
        params["security"] = params.get("security") or "reality"

    proxy["servername"] = params.get("sni") or params.get("peer")
    proxy["flow"] = params.get("flow")
    proxy["client-fingerprint"] = params.get("fp")
    proxy["alpn"] = [a.strip() for a in params["alpn"].split(",")] if params.get("alpn") else None
    skip_cert = params.get("allowinsecure") or params.get("allowInsecure") or params.get("skip-cert-verify") or ""
    proxy["skip-cert-verify"] = _truthy(skip_cert)

    if params.get("security") == "reality":
        ro: Dict[str, str] = {}
        if params.get("pbk"):
            ro["public-key"] = params["pbk"]
        if params.get("sid"):
            ro["short-id"] = params["sid"]
        if params.get("spx"):
            ro["spider-x"] = params["spx"]
        if params.get("pqv"):
            ro["mldsa65-verify"] = params["pqv"]
        if params.get("ech"):
            ro["ech"] = params["ech"]
        if ro:
            proxy["reality-opts"] = ro

    network = "tcp"
    t = params.get("type")
    if t in ("ws", "websocket"):
        network = "ws"
    elif t == "http":
        network = "http"
    elif t == "grpc":
        network = "grpc"
    elif t == "h2":
        network = "h2"
    proxy["network"] = network

    if network in ("ws", "http", "grpc", "h2"):
        opts: Dict[str, Any] = {}
        host = params.get("host") or params.get("obfsparam") or params.get("obfs-param")
        if host:
            try:
                if host.startswith("{") and host.endswith("}"):
                    opts["headers"] = json.loads(host)
                else:
                    opts["headers"] = {"Host": host}
            except (json.JSONDecodeError, ValueError):
                opts["headers"] = {"Host": host}
        if params.get("path"):
            opts["path"] = params["path"]
        if network == "ws" and params.get("headerType") == "http":
            opts["v2ray-http-upgrade"] = True
        if opts and network != "tcp":
            proxy[f"{network}-opts"] = opts

    if proxy.get("tls") and not proxy.get("servername"):
        wo = proxy.get("ws-opts")
        ho = proxy.get("http-opts")
        if wo and wo.get("headers", {}).get("Host"):
            proxy["servername"] = wo["headers"]["Host"]
        elif ho and ho.get("headers", {}).get("Host"):
            h = ho["headers"]["Host"]
            proxy["servername"] = h[0] if isinstance(h, list) else h

    return proxy


def _parse_userinfo_style(line: str, scheme: str):
    """供 trojan / anytls 复用的解析。"""
    body = re.split(rf"{scheme}://", line, maxsplit=1)[1]
    m = re.match(r"^(.*?)@(.*?)(?::(\d+))?/?(?:\?(.*?))?(?:#(.*?))?$", body)
    if not m:
        raise ValueError(f"Invalid {scheme} URI")
    password_raw, server_raw, port_str, addons, name_raw = m.groups()
    server = server_raw[1:-1] if server_raw.startswith("[") and server_raw.endswith("]") else server_raw
    port = int(port_str) if port_str else 443
    password = unquote(password_raw)
    decoded_name = trim_str(unquote(name_raw or ""))
    return server, port, password, (addons or ""), decoded_name


def uri_trojan(line: str) -> Dict[str, Any]:
    server, port, password, addons, decoded_name = _parse_userinfo_style(line, "trojan")
    name = decoded_name or f"Trojan {server}:{port}"

    proxy: Dict[str, Any] = {
        "type": "trojan", "name": name, "server": server, "port": port, "password": password,
    }
    host = ""
    path = ""
    for addon in addons.split("&"):
        k, _, v = addon.partition("=")
        v = unquote(v)
        if k == "type":
            proxy["network"] = v if v in ("ws", "h2") else "tcp"
        elif k == "host":
            host = v
        elif k == "path":
            path = v
        elif k == "alpn":
            proxy["alpn"] = v.split(",") if v else None
        elif k == "sni":
            proxy["sni"] = v
        elif k == "skip-cert-verify":
            proxy["skip-cert-verify"] = _truthy(v)
        elif k in ("fingerprint", "fp"):
            proxy["fingerprint"] = v
        elif k == "encryption":
            enc = v.split(";")
            if len(enc) == 3:
                proxy["ss-opts"] = {"enabled": True, "method": enc[1], "password": enc[2]}
        elif k == "client-fingerprint":
            proxy["client-fingerprint"] = v

    if proxy.get("network") == "ws":
        proxy["ws-opts"] = {"headers": {"Host": host}, "path": path}
    elif proxy.get("network") == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": path}
    return proxy


def uri_anytls(line: str) -> Dict[str, Any]:
    server, port, password, addons, decoded_name = _parse_userinfo_style(line, "anytls")
    name = decoded_name or f"anytls {server}:{port}"

    proxy: Dict[str, Any] = {
        "type": "anytls", "name": name, "server": server, "port": port, "password": password,
    }

    for addon in addons.split("&"):
        if not addon:
            continue
        k, _, v = addon.partition("=")
        v = unquote(v)
        if k == "sni":
            proxy["sni"] = v
        elif k == "alpn":
            proxy["alpn"] = [s.strip() for s in v.split(",")] if v else None
        elif k in ("fp", "fingerprint", "client-fingerprint"):
            proxy["client-fingerprint"] = v
        elif k in ("skip-cert-verify", "allowInsecure", "allow_insecure"):
            proxy["skip-cert-verify"] = _truthy(v)
        elif k == "udp":
            proxy["udp"] = _truthy(v)
        elif k == "idle-session-check-interval":
            proxy["idle-session-check-interval"] = int(v) if v else None
        elif k == "idle-session-timeout":
            proxy["idle-session-timeout"] = int(v) if v else None
        elif k == "min-idle-session":
            proxy["min-idle-session"] = int(v) if v else None

    return proxy


def uri_hysteria2(line: str) -> Dict[str, Any]:
    hash_idx = line.find("#")
    main_part = line[:hash_idx] if hash_idx != -1 else line
    name_part = line[hash_idx + 1:] if hash_idx != -1 else ""
    name = unquote(name_part) or "Hysteria2 Node"

    core = re.sub(r"^(hysteria2|hy2)://", "", main_part, flags=re.I)
    at_idx = core.rfind("@")
    if at_idx == -1:
        raise ValueError("No password (auth) found in hysteria2 link")
    password_raw = core[:at_idx]
    addr_and_query = core[at_idx + 1:]
    password = unquote(password_raw)

    addr, _, query = addr_and_query.partition("?")
    params = parse_query(query)

    colon_idx = addr.rfind(":")
    if colon_idx == -1:
        raise ValueError("No port found in hysteria2 link")
    server = addr[:colon_idx]
    try:
        port = int(addr[colon_idx + 1:])
    except ValueError:
        port = 443

    proxy: Dict[str, Any] = {
        "name": name.strip(), "type": "hysteria2",
        "server": server, "port": port, "password": password,
    }

    skip_v = params.get("skip-cert-verify") or ""
    if params.get("insecure") == "1" or skip_v == "1" or re.search(r"true", skip_v, re.I):
        proxy["skip-cert-verify"] = True
    if params.get("sni"):
        proxy["sni"] = params["sni"]
    if params.get("obfs"):
        proxy["obfs"] = params["obfs"]
    if params.get("obfs-password"):
        proxy["obfs-password"] = params["obfs-password"]
    if "alpn" in params:
        proxy["alpn"] = [a.strip() for a in params["alpn"].split(",") if a.strip()]
    if "fp" in params or "fingerprint" in params:
        proxy["fingerprint"] = params.get("fp") or params.get("fingerprint")
    if "pinSHA256" in params:
        proxy["fingerprint"] = params["pinSHA256"]

    return proxy


def uri_hysteria(line: str) -> Dict[str, Any]:
    body = re.split(r"(?:hysteria|hy)://", line, maxsplit=1)[1]
    m = re.match(r"^(.*?)(?::(\d+))?/?(?:\?(.*?))?(?:#(.*?))?$", body)
    if not m:
        raise ValueError("Invalid Hysteria URI")
    server, port_str, addons, name_raw = m.group(1), m.group(2), m.group(3) or "", m.group(4)
    port = int(port_str) if port_str else 443
    decoded_name = trim_str(unquote(name_raw or ""))
    name = decoded_name or f"Hysteria {server}:{port}"

    proxy: Dict[str, Any] = {"type": "hysteria", "name": name, "server": server, "port": port}
    peer_fallback = None

    for addon in addons.split("&"):
        k, _, v = addon.partition("=")
        k = k.replace("_", "-")
        v = unquote(v)
        if k == "alpn":
            proxy["alpn"] = v.split(",") if v else None
        elif k in ("insecure", "skip-cert-verify"):
            proxy["skip-cert-verify"] = _truthy(v)
        elif k == "auth":
            proxy["auth-str"] = v
        elif k == "mport":
            proxy["ports"] = v
        elif k == "obfsParam":
            proxy["obfs"] = v
        elif k == "upmbps":
            proxy["up"] = v
        elif k == "downmbps":
            proxy["down"] = v
        elif k == "obfs":
            proxy["obfs"] = v or ""
        elif k == "fast-open":
            proxy["fast-open"] = _truthy(v)
        elif k == "peer":
            peer_fallback = v
        elif k == "recv-window-conn":
            proxy["recv-window-conn"] = int(v)
        elif k == "recv-window":
            proxy["recv-window"] = int(v)
        elif k == "ca":
            proxy["ca"] = v
        elif k == "ca-str":
            proxy["ca-str"] = v
        elif k == "disable-mtu-discovery":
            proxy["disable-mtu-discovery"] = _truthy(v)
        elif k == "fingerprint":
            proxy["fingerprint"] = v
        elif k == "protocol":
            proxy["protocol"] = v
        elif k == "sni":
            proxy["sni"] = v

    if not proxy.get("sni") and peer_fallback:
        proxy["sni"] = peer_fallback
    if peer_fallback and peer_fallback != proxy.get("sni"):
        proxy["peer"] = peer_fallback
    if not proxy.get("protocol"):
        proxy["protocol"] = "udp"
    return proxy


def uri_tuic(line: str) -> Dict[str, Any]:
    body = re.split(r"tuic://", line, maxsplit=1)[1]
    m = re.match(r"^(.*?):(.*?)@(.*?)(?::(\d+))?/?(?:\?(.*?))?(?:#(.*?))?$", body)
    if not m:
        raise ValueError("Invalid TUIC URI")
    uuid, password_raw, server, port_str, addons, name_raw = m.groups()
    port = int(port_str) if port_str else 443
    password = unquote(password_raw)
    decoded_name = trim_str(unquote(name_raw or ""))
    name = decoded_name or f"TUIC {server}:{port}"

    proxy: Dict[str, Any] = {
        "type": "tuic", "name": name, "server": server, "port": port,
        "password": password, "uuid": uuid,
    }

    for addon in (addons or "").split("&"):
        k, _, v = addon.partition("=")
        k = k.replace("_", "-")
        v = unquote(v)
        if k == "token":
            proxy["token"] = v
        elif k == "ip":
            proxy["ip"] = v
        elif k == "heartbeat-interval":
            proxy["heartbeat-interval"] = int(v)
        elif k == "alpn":
            proxy["alpn"] = v.split(",") if v else None
        elif k == "disable-sni":
            proxy["disable-sni"] = _truthy(v)
        elif k == "reduce-rtt":
            proxy["reduce-rtt"] = _truthy(v)
        elif k == "request-timeout":
            proxy["request-timeout"] = int(v)
        elif k == "udp-relay-mode":
            proxy["udp-relay-mode"] = v
        elif k == "congestion-controller":
            proxy["congestion-controller"] = v
        elif k == "max-udp-relay-packet-size":
            proxy["max-udp-relay-packet-size"] = int(v)
        elif k == "fast-open":
            proxy["fast-open"] = _truthy(v)
        elif k == "skip-cert-verify":
            proxy["skip-cert-verify"] = _truthy(v)
        elif k == "max-open-streams":
            proxy["max-open-streams"] = int(v)
        elif k == "sni":
            proxy["sni"] = v
        elif k == "allow-insecure":
            proxy["skip-cert-verify"] = _truthy(v)

    return proxy


def uri_wireguard(line: str) -> Dict[str, Any]:
    body = re.split(r"(?:wireguard|wg)://", line, maxsplit=1)[1]
    m = re.match(r"^(?:(.*?)@)?(.*?)(?::(\d+))?/?(?:\?(.*?))?(?:#(.*?))?$", body)
    if not m:
        raise ValueError("Invalid WireGuard URI")
    private_key_raw, server, port_str, addons, name_raw = m.groups()
    port = int(port_str) if port_str else 443
    private_key = unquote(private_key_raw or "")
    decoded_name = trim_str(unquote(name_raw or ""))
    name = decoded_name or f"WireGuard {server}:{port}"

    proxy: Dict[str, Any] = {
        "type": "wireguard", "name": name, "server": server, "port": port,
        "private-key": private_key, "udp": True,
    }

    for addon in (addons or "").split("&"):
        k, _, v = addon.partition("=")
        k = k.replace("_", "-")
        v = unquote(v)
        if k in ("address", "ip"):
            for i in v.split(","):
                ip = re.sub(r"/\d+$", "", i.strip()).lstrip("[").rstrip("]")
                if is_ipv4(ip):
                    proxy["ip"] = ip
                elif is_ipv6(ip):
                    proxy["ipv6"] = ip
        elif k == "publickey":
            proxy["public-key"] = v
        elif k == "allowed-ips":
            proxy["allowed-ips"] = v.split(",")
        elif k == "pre-shared-key":
            proxy["pre-shared-key"] = v
        elif k == "reserved":
            parsed = []
            for i in v.split(","):
                try:
                    parsed.append(int(i.strip()))
                except ValueError:
                    pass
            if len(parsed) == 3:
                proxy["reserved"] = parsed
        elif k == "udp":
            proxy["udp"] = _truthy(v)
        elif k == "mtu":
            proxy["mtu"] = int(v.strip())
        elif k == "dialer-proxy":
            proxy["dialer-proxy"] = v
        elif k == "remote-dns-resolve":
            proxy["remote-dns-resolve"] = _truthy(v)
        elif k == "dns":
            proxy["dns"] = v.split(",")

    return proxy


def _parse_auth_style(line: str, scheme_pattern: str):
    body = re.split(scheme_pattern, line, maxsplit=1)[1]
    m = re.match(r"^(?:(.*?)@)?(.*?)(?::(\d+))?/?(?:\?(.*?))?(?:#(.*?))?$", body)
    if not m:
        raise ValueError(f"Invalid {scheme_pattern} URI")
    auth_raw, server, port_str, addons, name_raw = m.groups()
    port = int(port_str) if port_str else 443
    auth = unquote(auth_raw) if auth_raw else None
    decoded_name = trim_str(unquote(name_raw or ""))
    return auth, server, port, (addons or ""), decoded_name


def uri_http(line: str) -> Dict[str, Any]:
    auth, server, port, addons, decoded_name = _parse_auth_style(line, r"(?:http|https)://")
    name = decoded_name or f"HTTP {server}:{port}"

    proxy: Dict[str, Any] = {"type": "http", "name": name, "server": server, "port": port}
    if auth:
        username, _, password = auth.partition(":")
        proxy["username"] = username
        proxy["password"] = password

    for addon in addons.split("&"):
        k, _, v = addon.partition("=")
        k = k.replace("_", "-")
        v = unquote(v)
        if k == "tls":
            proxy["tls"] = _truthy(v)
        elif k == "fingerprint":
            proxy["fingerprint"] = v
        elif k == "skip-cert-verify":
            proxy["skip-cert-verify"] = _truthy(v)
        elif k == "ip-version":
            proxy["ip-version"] = v if v in ("dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer") else "dual"

    return proxy


def uri_socks(line: str) -> Dict[str, Any]:
    auth, server, port, addons, decoded_name = _parse_auth_style(line, r"socks5://")
    name = decoded_name or f"SOCKS5 {server}:{port}"

    proxy: Dict[str, Any] = {"type": "socks5", "name": name, "server": server, "port": port}
    if auth:
        username, _, password = auth.partition(":")
        proxy["username"] = username
        proxy["password"] = password

    for addon in addons.split("&"):
        k, _, v = addon.partition("=")
        k = k.replace("_", "-")
        v = unquote(v)
        if k == "tls":
            proxy["tls"] = _truthy(v)
        elif k == "fingerprint":
            proxy["fingerprint"] = v
        elif k == "skip-cert-verify":
            proxy["skip-cert-verify"] = _truthy(v)
        elif k == "udp":
            proxy["udp"] = _truthy(v)
        elif k == "ip-version":
            proxy["ip-version"] = v if v in ("dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer") else "dual"

    return proxy


# ============================================================
#  节点对象 → Clash YAML 片段
# ============================================================

def _clean_empty(obj):
    if obj is None:
        return None
    if isinstance(obj, list):
        arr = [_clean_empty(v) for v in obj]
        arr = [v for v in arr if v is not None]
        return arr if arr else None
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            cv = _clean_empty(v)
            if cv is None or cv == "":
                continue
            if isinstance(cv, (dict, list)) and len(cv) == 0:
                continue
            cleaned[k] = cv
        return cleaned if cleaned else None
    return obj


def generate_clash_node(node: Dict[str, Any]) -> str:
    fallback_name = node.get("name") or f"{(node.get('type') or 'Node').upper()} {node.get('server')}:{node.get('port')}"
    clash_node: Dict[str, Any] = {
        "name": fallback_name,
        "type": node.get("type"),
        "server": punycode_domain(node["server"]) if node.get("server") else node.get("server"),
        "port": node.get("port"),
    }

    handled = {"name", "server", "port", "type"}
    for field, value in node.items():
        if field in handled or field.startswith("_"):
            continue
        if value is not None and value != "":
            clash_node[field] = value

    if node.get("sni") and not clash_node.get("servername"):
        clash_node["servername"] = node["sni"]

    cleaned = _clean_empty(clash_node) or {}

    if yaml is not None:
        text = yaml.dump(
            cleaned, allow_unicode=True, default_flow_style=False,
            sort_keys=False, indent=2,
        ).rstrip("\n")
    else:
        text = "\n".join(f"{k}: {v}" for k, v in cleaned.items())

    lines = text.split("\n")
    result = "- " + lines[0]
    for line in lines[1:]:
        result += "\n  " + line
    return result


# ============================================================
#  节点对象 → 分享链接
# ============================================================

def generate_uri(node: Dict[str, Any]) -> str:
    name = quote(str(node.get("name") or "Node"), safe="")
    server = punycode_domain(node["server"]) if node.get("server") else node.get("server")
    port = node.get("port")
    t = node.get("type")

    if t == "ss":
        auth = utf8_to_base64(f"{node.get('cipher') or 'auto'}:{node.get('password') or ''}")
        return f"ss://{auth}@{server}:{port}#{name}"

    if t == "vmess":
        vmess = {
            "v": "2", "ps": node.get("name"), "add": server, "port": port,
            "id": node.get("uuid"), "aid": node.get("alterId") or 0,
            "scy": node.get("cipher") or "auto",
            "net": node.get("network") or "tcp", "type": "none",
            "host": (node.get("ws-opts") or {}).get("headers", {}).get("Host") or "",
            "path": (node.get("ws-opts") or {}).get("path") or (node.get("grpc-opts") or {}).get("grpc-service-name") or "",
            "tls": "tls" if node.get("tls") else "none",
            "sni": node.get("servername") or "",
            "alpn": ",".join(node.get("alpn") or []),
            "fp": node.get("fingerprint") or node.get("client-fingerprint") or "",
        }
        return f"vmess://{utf8_to_base64(json.dumps(vmess, ensure_ascii=False))}"

    if t == "vless":
        link = f"vless://{node.get('uuid')}@{server}:{port}"
        params: Dict[str, str] = {"type": node.get("network") or "tcp", "encryption": "none"}
        if node.get("flow"):
            params["flow"] = node["flow"]
        if node.get("tls") or node.get("reality-opts"):
            is_reality = bool(node.get("reality-opts"))
            params["security"] = "reality" if is_reality else "tls"
            if node.get("servername") or node.get("sni"):
                params["sni"] = node.get("servername") or node.get("sni")
            if node.get("fingerprint") or node.get("client-fingerprint"):
                params["fp"] = node.get("fingerprint") or node.get("client-fingerprint")
            if node.get("skip-cert-verify"):
                params["allowInsecure"] = "1"
            if isinstance(node.get("alpn"), list) and node["alpn"]:
                params["alpn"] = ",".join(node["alpn"])
            if is_reality:
                ro = node["reality-opts"]
                if ro.get("public-key"):
                    params["pbk"] = ro["public-key"]
                if ro.get("short-id"):
                    params["sid"] = ro["short-id"]
                if ro.get("spider-x"):
                    params["spx"] = ro["spider-x"]
                if ro.get("mldsa65-verify"):
                    params["pqv"] = ro["mldsa65-verify"]
                if ro.get("ech"):
                    params["ech"] = ro["ech"]
        return link + "?" + urlencode(params) + f"#{name}"

    if t == "trojan":
        link = f"trojan://{quote(str(node.get('password') or ''), safe='')}@{server}:{port}"
        params = {}
        if node.get("network") and node["network"] != "tcp":
            params["type"] = node["network"]
        if node.get("sni") or node.get("servername"):
            params["sni"] = node.get("sni") or node.get("servername")
        if node.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        if node.get("fingerprint"):
            params["fp"] = node["fingerprint"]
        qs = urlencode(params) if params else ""
        return link + (f"?{qs}" if qs else "") + f"#{name}"

    if t == "anytls":
        link = f"anytls://{quote(str(node.get('password') or ''), safe='')}@{server}:{port}"
        params = {}
        if node.get("sni"):
            params["sni"] = node["sni"]
        if isinstance(node.get("alpn"), list) and node["alpn"]:
            params["alpn"] = ",".join(node["alpn"])
        if node.get("client-fingerprint"):
            params["client-fingerprint"] = node["client-fingerprint"]
        if node.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        if node.get("udp"):
            params["udp"] = "1"
        for key in ("idle-session-check-interval", "idle-session-timeout", "min-idle-session"):
            if node.get(key):
                params[key] = str(node[key])
        qs = urlencode(params) if params else ""
        return link + (f"?{qs}" if qs else "") + f"#{name}"

    if t == "hysteria2":
        link = f"hysteria2://{quote(str(node.get('password') or ''), safe='')}@{server}:{port}"
        params = {}
        if node.get("sni"):
            params["sni"] = node["sni"]
        if node.get("obfs"):
            params["obfs"] = node["obfs"]
        if node.get("obfs-password"):
            params["obfs-password"] = node["obfs-password"]
        if node.get("skip-cert-verify"):
            params["insecure"] = "1"
        if isinstance(node.get("alpn"), list) and node["alpn"]:
            params["alpn"] = ",".join(node["alpn"])
        qs = urlencode(params) if params else ""
        return link + (f"?{qs}" if qs else "") + f"#{name}"

    if t == "tuic":
        link = f"tuic://{node.get('uuid')}:{quote(str(node.get('password') or ''), safe='')}@{server}:{port}"
        params = {}
        if node.get("sni"):
            params["sni"] = node["sni"]
        if isinstance(node.get("alpn"), list) and node["alpn"]:
            params["alpn"] = ",".join(node["alpn"])
        if node.get("skip-cert-verify"):
            params["allow_insecure"] = "1"
        qs = urlencode(params) if params else ""
        return link + (f"?{qs}" if qs else "") + f"#{name}"

    if t == "hysteria":
        link = f"hysteria://{server}:{port}"
        params = {}
        if node.get("protocol"):
            params["protocol"] = node["protocol"]
        if node.get("auth-str"):
            params["auth"] = node["auth-str"]
        if node.get("sni"):
            params["sni"] = node["sni"]
        if node.get("up"):
            params["upmbps"] = str(node["up"])
        if node.get("down"):
            params["downmbps"] = str(node["down"])
        if isinstance(node.get("alpn"), list) and node["alpn"]:
            params["alpn"] = ",".join(node["alpn"])
        if node.get("obfs"):
            params["obfs"] = node["obfs"]
        if node.get("ports"):
            params["mport"] = str(node["ports"])
        if node.get("skip-cert-verify"):
            params["insecure"] = "1"
        qs = urlencode(params) if params else ""
        return link + (f"?{qs}" if qs else "") + f"#{name}"

    if t == "wireguard":
        wg_key = quote(str(node.get("private-key") or ""), safe="")
        link = f"wireguard://{wg_key}@{server}:{port}"
        params = {}
        if node.get("public-key"):
            params["public-key"] = node["public-key"]
        addrs = [a for a in [node.get("ip"), node.get("ipv6")] if a]
        if addrs:
            params["address"] = ",".join(addrs)
        if isinstance(node.get("allowed-ips"), list) and node["allowed-ips"]:
            params["allowed-ips"] = ",".join(node["allowed-ips"])
        if node.get("pre-shared-key"):
            params["pre-shared-key"] = node["pre-shared-key"]
        if isinstance(node.get("reserved"), list) and len(node["reserved"]) == 3:
            params["reserved"] = ",".join(str(x) for x in node["reserved"])
        if node.get("mtu"):
            params["mtu"] = str(node["mtu"])
        if isinstance(node.get("dns"), list) and node["dns"]:
            params["dns"] = ",".join(node["dns"])
        qs = urlencode(params) if params else ""
        return link + (f"?{qs}" if qs else "") + f"#{name}"

    if t == "http":
        has_auth = bool(node.get("username") or node.get("password"))
        http_auth = (
            f"{quote(str(node.get('username') or ''), safe='')}:{quote(str(node.get('password') or ''), safe='')}@"
            if has_auth else ""
        )
        link = f"http://{http_auth}{server}:{port}"
        params = {}
        if node.get("tls"):
            params["tls"] = "1"
        if node.get("fingerprint"):
            params["fingerprint"] = node["fingerprint"]
        if node.get("skip-cert-verify"):
            params["skip-cert-verify"] = "1"
        if node.get("ip-version"):
            params["ip-version"] = node["ip-version"]
        qs = urlencode(params) if params else ""
        return link + (f"?{qs}" if qs else "") + f"#{name}"

    if t == "socks5":
        has_auth = bool(node.get("username") or node.get("password"))
        socks_auth = (
            f"{quote(str(node.get('username') or ''), safe='')}:{quote(str(node.get('password') or ''), safe='')}@"
            if has_auth else ""
        )
        link = f"socks5://{socks_auth}{server}:{port}"
        params = {}
        if node.get("tls"):
            params["tls"] = "1"
        if node.get("fingerprint"):
            params["fingerprint"] = node["fingerprint"]
        if node.get("skip-cert-verify"):
            params["skip-cert-verify"] = "1"
        if node.get("udp"):
            params["udp"] = "1"
        if node.get("ip-version"):
            params["ip-version"] = node["ip-version"]
        qs = urlencode(params) if params else ""
        return link + (f"?{qs}" if qs else "") + f"#{name}"

    print(f"Unknown proxy type: {t}")
    return ""


# ============================================================
#  顶层 API
# ============================================================

def try_decode_base64_subscription_links(links: List[str]) -> Optional[List[str]]:
    raw = "\n".join(links).strip()
    if not raw:
        return None
    normalized = re.sub(r"\s+", "", raw).replace("-", "+").replace("_", "/")
    if not re.match(r"^[A-Za-z0-9+/=]+$", normalized):
        return None
    padded = _pad_b64(normalized)
    decoded = decode_base64_strict(padded)
    if decoded is None:
        return None
    decoded_links = [ln.strip() for ln in decoded.splitlines() if ln.strip()]
    if not any(re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", ln) for ln in decoded_links):
        return None
    return decoded_links


def _links_to_clash_nodes(links: List[str]) -> List[str]:
    out: List[str] = []
    for link in links:
        try:
            node = parse_uri(link.strip())
            if node:
                n = generate_clash_node(node)
                if n:
                    out.append(n)
        except Exception as e:
            print(e)
    return out


def link_to_clash(links: List[str], mode: str = "proxies") -> Dict[str, Any]:
    node_strings = _links_to_clash_nodes(links)

    if not node_strings:
        decoded = try_decode_base64_subscription_links(links)
        if decoded:
            node_strings = _links_to_clash_nodes(decoded)

    if not node_strings:
        return {
            "success": False,
            "data": "# 无有效节点 (请检查链接格式是否正确)\n# No valid node (please check link format)",
        }

    content = "\n".join(node_strings)
    if mode == "payload":
        return {"success": True, "data": f"payload:\n{content}"}
    if mode == "none":
        return {"success": True, "data": content}
    return {"success": True, "data": f"proxies:\n{content}"}


def clash_to_link(yaml_text: str) -> Dict[str, Any]:
    try:
        yaml_text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]", "", yaml_text)

        if yaml is None:
            return {"success": False, "data": "# pyyaml 未安装\n# pyyaml not installed"}

        try:
            config = yaml.safe_load(yaml_text)
        except yaml.YAMLError as e:
            return {"success": False, "data": f"# YAML 解析失败: {e}"}

        candidates: List[Any] = []
        if isinstance(config, dict):
            for key in ("proxies", "Proxy", "payload"):
                if key in config:
                    candidates.append(config[key])
            providers = config.get("proxy-providers")
            if isinstance(providers, dict):
                for p in providers.values():
                    if isinstance(p, dict):
                        if p.get("proxies"):
                            candidates.append(p["proxies"])
                        if p.get("payload"):
                            candidates.append(p["payload"])
        elif isinstance(config, list):
            candidates.append(config)

        flat: List[dict] = []
        for c in candidates:
            if isinstance(c, list):
                flat.extend(item for item in c if isinstance(item, dict))

        seen = set()
        proxies: List[dict] = []
        for node in flat:
            if node.get("name") and node.get("server") and node.get("port"):
                key = f"{node.get('type')}|{node.get('name')}|{node.get('server')}|{node.get('port')}"
                if key not in seen:
                    seen.add(key)
                    proxies.append(node)

        if not proxies:
            return {
                "success": False,
                "data": "# 未检测到任何节点 (支持: proxies / payload / 节点数组)\n# No valid node found",
            }

        links = [generate_uri(n) for n in proxies]
        links = [l for l in links if l]
        return {"success": True, "data": "\n".join(links)}

    except Exception as e:
        return {"success": False, "data": f"# YAML 解析失败: {e}"}


# ============================================================
#  命令行入口
# ============================================================

def _read_input(path: str) -> str:
    """从文件或 stdin 读入（path='-' 时读 stdin）。"""
    if path == "-":
        import sys
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _write_output(path: Optional[str], content: str) -> None:
    """写到文件或 stdout（path 为 None 或 '-' 时写 stdout）。"""
    if path is None or path == "-":
        print(content)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="converter",
        description="订阅链接 ⇄ Clash 配置 双向转换器",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- 链接 → Clash
    p1 = sub.add_parser("to-clash", help="链接 → Clash 配置")
    p1.add_argument("input", help="输入文件，'-' 表示 stdin")
    p1.add_argument("-o", "--output", default="-", help="输出文件，默认 stdout")
    p1.add_argument(
        "-m", "--mode",
        choices=["proxies", "payload", "none"],
        default="proxies",
        help="输出模式（默认 proxies）",
    )

    # ---- Clash → 链接
    p2 = sub.add_parser("to-link", help="Clash 配置 → 链接")
    p2.add_argument("input", help="输入文件，'-' 表示 stdin")
    p2.add_argument("-o", "--output", default="-", help="输出文件，默认 stdout")

    # ---- 演示
    sub.add_parser("demo", help="运行内置演示")

    args = parser.parse_args(argv)

    if args.command == "to-clash":
        text = _read_input(args.input)
        links = [ln.strip() for ln in text.splitlines() if ln.strip()]
        result = link_to_clash(links, mode=args.mode)
        _write_output(args.output, result["data"])
        return 0 if result["success"] else 1

    if args.command == "to-link":
        text = _read_input(args.input)
        result = clash_to_link(text)
        _write_output(args.output, result["data"])
        return 0 if result["success"] else 1

    if args.command == "demo":
        _demo()
        return 0

    return 0


def _demo() -> None:
    """内置演示：链接 → Clash → 链接，验证双向一致性。"""
    sample_links = [
            "dHJvamFuOi8vaHVtYW5pdHlAMjE2LjI0LjU3Ljc6NDQzP3NuaT13d3cuaWduaXRlbGltaXQuY29tJnR5cGU9d3MmcGF0aD0lMkZhc3NpZ25tZW50JmFscG49aHR0cCUyRjEuMSZmcD1jaHJvbWUjJUYwJTlGJTg3JUFCJUYwJTlGJTg3JUI3RlJfMSU3QzUxN0tCJTJGcwp0cm9qYW46Ly9odW1hbml0eUAxNjIuMTU5LjEzNi4yMzQ6NDQzP3NuaT13d3cuaWduaXRlbGltaXQuY29tJnR5cGU9d3MmcGF0aD0lMkZhc3NpZ25tZW50JmFscG49aDIlMkNodHRwJTJGMS4xJmZwPWNocm9tZSMlRjAlOUYlODclQUIlRjAlOUYlODclQjdGUl8yJTdDODA5S0IlMkZzCnZsZXNzOi8vYmQ5OWRhOTctMjY1ZS0wMDIxLTgyY2MtNGVjMDA5ZmU5Y2UyQDUuNjEuOTEuMjA2OjQ0Mz9zZWN1cml0eT1yZWFsaXR5JnR5cGU9dGNwJnNuaT13d3cuYW1kLmNvbSZmcD1maXJlZm94JmZsb3c9eHRscy1ycHJ4LXZpc2lvbiZzaWQ9MGE0YjdjM2QmcGJrPWI0bjFwY084U1QzSmtHdGo4WXltWFZyVzE3TEVlMkVIZWM1d1k3aE1NUjQmZW5jcnlwdGlvbj1ub25lIyVGMCU5RiU4NyVBQiVGMCU5RiU4NyVBRUZJXzElN0MxLjJNQiUyRnMKdHJvamFuOi8vaHVtYW5pdHlAMTY1LjIxNS4yNTAuMTQ6NDQzP3NuaT13d3cuaWduaXRlbGltaXQuY29tJmFsbG93SW5zZWN1cmU9MSZ0eXBlPXdzJnBhdGg9JTJGYXNzaWdubWVudCZmcD1jaHJvbWUjJUYwJTlGJTg3JUFCJUYwJTlGJTg3JUI3RlJfMyU3QzcxM0tCJTJGcwpoeXN0ZXJpYTI6Ly9tYWludGVsbEAxNTIuNzAuMjM3LjEyMzoyMDUzP2luc2VjdXJlPTEmc25pPWJpbmcuY29tIyVGMCU5RiU4NyVCMCVGMCU5RiU4NyVCN0tSXzElN0M1NDJLQiUyRnMKdm1lc3M6Ly9leUoySWpvaU1pSXNJbkJ6SWpvaThKK0hwL0NmaDdkQ1VsOHhmRGc0TkV0Q0wzTWlMQ0poWkdRaU9pSnBjRFl0WW5JMUxuWndNVEF3TUM1dVpYUWlMQ0p3YjNKMElqb2lORFF6SWl3aWFXUWlPaUprT1dKalpqbGtaQzAyT1RCakxUUTVZall0T0RnNU55MDBOamsxT1RVM01tSmtNVGdpTENKaGFXUWlPaUl3SWl3aWMyTjVJam9pWVhWMGJ5SXNJbTVsZENJNkluZHpJaXdpZEhsd1pTSTZJaUlzSW5Sc2N5STZJblJzY3lJc0luTnVhU0k2SW1KeUxuWndNVEF3TUM1dVpYUWlMQ0p3WVhSb0lqb2lMM0IxYkdsamNFUnBjMjVsZVNJc0ltaHZjM1FpT2lKaWNpNTJjREV3TURBdWJtVjBJbjA9Cmh5c3RlcmlhMjovLzFjYzVkMTk4LTQ5MjktNGEyMS04ZWU4LTMxMWY4MWIwMzQ5N0Bqanouamp6bm9kZW5vZGUudG9wOjM5OTk5P29iZnM9c2FsYW1hbmRlciZvYmZzLXBhc3N3b3JkPXVxbWdGWm1WTkhOWUd4YUgmc25pPWpqei5qanpub2Rlbm9kZS50b3AjJUYwJTlGJTg3JUI4JUYwJTlGJTg3JUFDU0dfMSU3QzIuOE1CJTJGcwp2bGVzczovL2VmNWM1ZDVjLTA4YzYtNDU0OS1iMDVlLWQxZmYyOWVjYzhiYUAxNzIuNjcuMjA2LjY0OjQ0Mz9zZWN1cml0eT10bHMmdHlwZT13cyZwYXRoPSUyRkpScjZWR2NTTEZjMDM0REM2c0Rid3lXSkxiQiZob3N0PTMtTTE2LmF5VVR0aEFZYTIwMzIua2ROcy5GUiZzbmk9My1NMTYuYXlVVHRoQVlhMjAzMi5rZE5zLkZSJmZwPWNocm9tZSMlRjAlOUYlODclQkElRjAlOUYlODclQjhVU18xJTdDMi40TUIlMkZzCnZsZXNzOi8vZWY1YzVkNWMtMDhjNi00NTQ5LWIwNWUtZDFmZjI5ZWNjOGJhQDE3Mi42Ny4xNjkuMzU6NDQzP3NlY3VyaXR5PXRscyZ0eXBlPXdzJnBhdGg9JTJGSlJyNlZHY1NMRmMwMzREQzZzRGJ3eVdKTGJCJmhvc3Q9Ny1NMTYucEF0dEFZYS04LmtkblMuZlImc25pPTctTTE2LnBBdHRBWWEtOC5rZG5TLmZSJmZwPWNocm9tZSMlRjAlOUYlODclQkElRjAlOUYlODclQjhVU18yJTdDMi4xTUIlMkZzCnZsZXNzOi8vZDQyN2EwMmYtZTBlYS0wMDIxLTljZmItNjZjMTg2NmNhM2NlQDUuNjEuOTEuMjA2OjQ0Mz9zZWN1cml0eT1yZWFsaXR5JnR5cGU9dGNwJnNuaT1jZG4tdXAucGVyZWNiYXNzLnJ1JmZwPWZpcmVmb3gmZmxvdz14dGxzLXJwcngtdmlzaW9uJnNpZD02YTJiNWM5ZCZwYms9YjRuMXBjTzhTVDNKa0d0ajhZeW1YVnJXMTdMRWUyRUhlYzV3WTdoTU1SNCZlbmNyeXB0aW9uPW5vbmUjJUYwJTlGJTg3JUFCJUYwJTlGJTg3JUFFRklfMiU3QzIuMU1CJTJGcw=="
    ]

    print("=" * 60)
    print("【1】链接 → Clash")
    print("=" * 60)
    r = link_to_clash(sample_links, mode="proxies")
    print(r["data"])
    print()

    print("=" * 60)
    print("【2】Clash → 链接")
    print("=" * 60)
    r2 = clash_to_link(r["data"])
    print(r2["data"])
    print()

    print("=" * 60)
    print("【3】Base64 订阅解码演示")
    print("=" * 60)
    import base64 as _b64
    b64_sub = _b64.b64encode("\n".join(sample_links).encode()).decode()
    r3 = link_to_clash([b64_sub], mode="none")
    print(r3["data"])


if __name__ == "__main__":
    import sys
    sys.exit(main())