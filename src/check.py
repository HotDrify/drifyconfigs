import asyncio
import base64
import os
import ssl
import time
from urllib.parse import urlparse

from config import CON, MAX_MS, TARGETS, TIMEOUT
from parser import parse, checksni
from ws import (
    server_ok,
    trojan_hand,
    vless_hend,
    ws_recv,
    ws_send,
)


async def check(config: str, timeout: float):
    info = parse(config)
    if not info or info["security"] == "reality":
        return None

    proto = info["proto"]
    security = info["security"]
    net = info["net"]

    can_handshake = (
        proto in ("vless", "trojan")
        and "flow=" not in config
        and security in ("none", "tls")
    )
    if security == "tls":
        sni = checksni(info["sni"])
        if info["sni"] and sni is None:
            return None
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                info["host"], info["port"],
                ssl=context, server_hostname=sni,
            ),
            timeout,
        )

    started = time.monotonic()
    writer = None
    try:
        if security == "tls":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    info["host"], info["port"],
                    ssl=context, server_hostname=info["sni"],
                ),
                timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(info["host"], info["port"]),
                timeout,
            )

        if net == "ws":
            request = (
                f"GET {info['path']} HTTP/1.1\r\n"
                f"Host: {info['header']}\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Key: "
                f"{base64.b64encode(os.urandom(16)).decode()}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            )
            writer.write(request.encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(500), timeout)
            if b" 101 " not in response.split(b"\r\n", 1)[0]:
                return None

        if can_handshake:
            parsed = urlparse(config)
            for target_host, target_port, request in TARGETS:
                if proto == "vless":
                    handshake = vless_hend(
                        parsed.username or "",
                        target_host, target_port, request,
                    )
                else:
                    handshake = trojan_hand(
                        parsed.password or parsed.username or "",
                        target_host, target_port, request,
                    )
                if not handshake:
                    continue
                try:
                    if net == "ws":
                        await ws_send(writer, handshake)
                        response = await ws_recv(reader, timeout)
                    else:
                        writer.write(handshake)
                        await writer.drain()
                        response = await asyncio.wait_for(
                            reader.read(4000), timeout
                        )
                except (OSError, TimeoutError):
                    return None
                if server_ok(response, proto):
                    return int((time.monotonic() - started) * 1000)
            return None

        return int((time.monotonic() - started) * 1000)

    except (OSError, TimeoutError, ValueError):
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
            except BaseException:
                pass
            try:
                await asyncio.wait_for(writer.wait_closed(), 1.0)
            except BaseException:
                pass

async def check_all(configs: list) -> dict:
    semaphore = asyncio.Semaphore(CON)
    lock = asyncio.Lock()
    results: dict = {}

    async def check_one(config):
        try:
            async with semaphore:
                latency = await check(config, TIMEOUT)
        except BaseException:
            latency = None
        async with lock:
            if latency is not None and latency <= MAX_MS:
                results[config] = latency

    await asyncio.gather(
        *(check_one(c) for c in configs),
        return_exceptions=True,
    )
    return results
