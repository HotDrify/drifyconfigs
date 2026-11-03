import asyncio
import hashlib
import ipaddress
import os
import struct
import uuid

from config import IS_OK


async def ws_send(writer, payload: bytes):
    mask = os.urandom(4)
    length = len(payload)
    header = bytearray([0x82])

    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header += struct.pack('>H', length)
    else:
        header.append(0x80 | 127)
        header += struct.pack('>Q', length)

    writer.write(
        bytes(header)
        + mask
        + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    )
    await writer.drain()


async def ws_recv(reader, timeout, max_size=4000) -> bytes:
    out = bytearray()
    try:
        while len(out) < max_size:
            header = await asyncio.wait_for(reader.readexactly(2), timeout)
            opcode = header[0] & 0x0F
            length = header[1] & 0x7F
            if length == 126:
                length = struct.unpack(
                    '>H',
                    await asyncio.wait_for(reader.readexactly(2), timeout),
                )[0]
            elif length == 127:
                length = struct.unpack(
                    '>Q',
                    await asyncio.wait_for(reader.readexactly(8), timeout),
                )[0]

            if header[1] & 0x80:
                mask = await asyncio.wait_for(
                    reader.readexactly(4), timeout
                )
            else:
                mask = None

            payload = await asyncio.wait_for(
                reader.readexactly(length), timeout
            )

            if mask:
                payload = bytes(
                    b ^ mask[i % 4]
                    for i, b in enumerate(payload)
                )

            if opcode == 0x08:
                break

            out.extend(payload)
            if len(payload) < 1024:
                break

    except (TimeoutError, asyncio.IncompleteReadError):
        pass

    return bytes(out)


def addrencode(host: str) -> bytes:
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            return b'\x01' + ip.packed
        return b'\x03' + ip.packed
    except ValueError:
        hostby = host.encode()
        return b'\x02' + bytes([len(hostby)]) + hostby


def vless_hend(uuidstr: str, host: str, port: int, payload: bytes) -> bytes | None:
    try:
        userid = uuid.UUID(uuidstr).bytes
    except ValueError:
        return None
    return (
        bytes([0])
        + userid
        + b'\x00\x01'
        + struct.pack('>H', port)
        + addrencode(host)
        + payload
    )


def trojan_hand(password: str, host: str, port: int, payload: bytes) -> bytes:
    return (
        hashlib.sha224(password.encode()).hexdigest().encode()
        + b'\r\n\x01'
        + addrencode(host)
        + struct.pack('>H', port)
        + b'\r\n'
        + payload
    )


def server_ok(resp: bytes, proto: str) -> bool:
    if not resp:
        return False
    if proto == "vless":
        if len(resp) < 2 or resp[0] != 0:
            return False
        resp = resp[2 + resp[1]:]
    return any(marker in resp[:200] for marker in IS_OK)
