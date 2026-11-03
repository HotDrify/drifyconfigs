import base64
import json
from urllib.parse import parse_qs, urlparse
import ipaddress

from config import CFPREF


def decode(data: str) -> bytes:
    data = data.strip().replace('-', '+').replace('_', '/')
    data += '=' * (-len(data) % 4)
    return base64.b64decode(data)


def valid(host, port) -> bool:
    return bool(
        host and port
        and 1 <= port <= 65535
        and host not in (
            "127.0.0.1", "0.0.0.0",
            "localhost", "::1",
        )
        and " " not in host
    )


def parse(config: str) -> dict | None:
    try:
        if config.startswith('vmess://'):
            data = json.loads(decode(config[8:].split('#')[0]) or b'{}')

            host = data.get('add') or data.get('host')
            port = int(str(data.get('port') or '443'))
            if not valid(host, port):
                return None

            sec = (
                'tls'
                if str(data.get('tls', '')).lower() in ('tls', 'true')
                else 'none'
            )
            if sec == 'tls' and host.startswith(CFPREF) and not data.get('sni'):
                return None

            sni = data.get('sni') or data.get('host') or host

            return {
                'host': host,
                'port': port,
                'sni': sni,
                'header': data.get('host') or sni,
                'security': sec,
                'net': data.get('net') or 'tcp',
                'path': data.get('path') or '/',
                'proto': 'vmess',
            }

        if config.startswith('ss://'):
            body = config[5:].split('#')[0].strip()
            if '@' in body:
                hostinf = body.rsplit('@', 1)[1].split('?')[0]
            else:
                hostinf = (
                    decode(body).decode('utf-8', 'ignore')
                    .rsplit('@', 1)[-1]
                )

            parsed = urlparse('ss://' + hostinf)
            if not valid(parsed.hostname, parsed.port):
                return None

            return {
                'host': parsed.hostname,
                'port': parsed.port,
                'sni': '',
                'header': '',
                'security': 'none',
                'net': 'tcp',
                'path': '/',
                'proto': 'ss',
            }

        parsed = urlparse(config)
        query = {
            k: v[0]
            for k, v in parse_qs(parsed.query, keep_blank_values=True).items()
        }
        port = parsed.port or 443
        if not valid(parsed.hostname, port):
            return None

        sec = query.get('security', 'none')
        if (
            sec in ('tls', 'reality')
            and parsed.hostname.startswith(CFPREF)
            and not query.get('sni')
            and not query.get('host')
        ):
            return None

        sni = query.get('sni') or query.get('host') or parsed.hostname

        return {
            'host': parsed.hostname,
            'port': port,
            'sni': sni,
            'header': query.get('host') or sni,
            'security': sec,
            'net': query.get('type', 'tcp'),
            'path': query.get('path') or '/',
            'proto': config.split('://', 1)[0],
        }

    except (ValueError, TypeError, AttributeError):
        return None


def serverid(config: str) -> str:
    if config.startswith('vmess://'):
        try:
            data = json.loads(decode(config[8:].split('#')[0]) or b'{}')
            return (
                f"vmess|{data.get('add')}|"
                f"{data.get('port')}|{data.get('id')}"
            )
        except (ValueError, AttributeError):
            return config

    try:
        parsed = urlparse(config)
        query = {
            k: v[0]
            for k, v in parse_qs(parsed.query, keep_blank_values=True).items()
        }
        return '|'.join([
            config.split('://', 1)[0],
            parsed.hostname or '',
            str(parsed.port or ''),
            parsed.username or parsed.password or '',
            query.get('sni', ''),
            query.get('path', ''),
            query.get('type', ''),
        ])
    except ValueError:
        return config

def rename(config: str, tag: str) -> str:
    if not config.startswith("vmess://"):
        return config
    try:
        data = json.loads(decode(config[8:].split("#")[0]))
        data["ps"] = tag
    except (ValueError, TypeError):
        return config

    return "vmess://" + base64.b64encode(
        json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    ).decode()

def checksni(host: str) -> str | None:
    if not host or len(host) > 253:
        return None
    host = host.strip().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    for label in host.split("."):
        if not label or len(label) > 63:
            return None
        if label[0] == "-" or label[-1] == "-":
            return None
        if not all(c.isalnum() or c == "-" for c in label):
            return None
    return host or None
