import os
import re

DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUB = os.path.join(DIR, "subscribes")
README = os.path.join(DIR, "README.md")

CON = 300
TIMEOUT = 5.0
SOURCES_TIMEOUT = 15
MAX_SOURCE = 5000
MAX_MS = 3000

NAME = "Drify_Configs"

SOURCES = [
    "https://github.com/igareck/vpn-configs-for-russia/raw/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://github.com/barry-far/V2ray-Config/raw/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/1.2.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
    "https://gitverse.ru/api/repos/cid-uskoritel/cid-white/raw/branch/master/whitelist.txt",
    "https://github.com/Epodonios/v2ray-configs/raw/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/26.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/refs/heads/main/conf-week.txt",
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub1.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub2.txt",
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/FSystem88/vless-keys/refs/heads/main/keys.txt",
    "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/26.txt",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/23.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/config/protocols/vless.txt",
]

PATTERN = re.compile(
    r'(vmess://[^\s"\'<>]+|'
    r'vless://[^\s"\'<>]+|'
    r'ss://[^\s"\'<>]+|'
    r'trojan://[^\s"\'<>]+)'
)

CFPREF = (
    "104.16.", "104.17.", "104.18.", "104.19.",
    "172.64.", "172.65.", "172.66.", "172.67.",
    "188.114.", "162.159.",
)

TARGETS = [
    (
        "1.1.1.1",
        80,
        (
            b"GET / HTTP/1.1\r\nHost: one.one.one.one\r\n"
            b"User-Agent: Mozzila/5.0\r\nConnection: close\n\r\n"
        ),
    ),
    (
        "cp.cloudflare.com",
        80,
        (
            b"GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\n"
            b"User-Agent: Mozzila/5.0\r\nConnection: close\n\r\n"
        ),
    ),
]

IS_OK = (
    b"HTTP/1.1 200", b"HTTP/1.0 200", b"HTTP/2 200",
    b"HTTP/1.1 204", b"HTTP/2 204",
    b"HTTP/1.1 301", b"HTTP/1.1 302",
)
