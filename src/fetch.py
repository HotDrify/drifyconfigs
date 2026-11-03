import asyncio
import re

import aiohttp

from config import MAX_SOURCE, PATTERN, SOURCES, SOURCES_TIMEOUT
from parser import decode, serverid


async def fetchall():
    timeout = aiohttp.ClientTimeout(total=SOURCES_TIMEOUT)
    async with aiohttp.ClientSession(
        timeout=timeout, headers={"User-Agent": "Mozilla/5.0"}
    ) as session:

        async def fetch_one(index, url):
            try:
                async with session.get(url) as response:
                    text = (
                        await response.text()
                        if response.status == 200 else ""
                    )
            except (aiohttp.ClientError, TimeoutError, OSError):
                text = ""

            configs = PATTERN.findall(text)
            if not configs and text:
                try:
                    decoded = decode(
                        re.sub(r"\s+", "", text)
                    ).decode("utf-8", "ignore")
                    configs = PATTERN.findall(decoded)
                except ValueError:
                    configs = []

            status = "ok" if configs else "empty" if text else "fail"
            return index, configs[:MAX_SOURCE], status

        tasks = [fetch_one(i, url) for i, url in enumerate(SOURCES)]
        return sorted(
            await asyncio.gather(*tasks),
            key=lambda item: item[0],
        )


def deduplicate(fetch_results) -> list:
    seen: dict = {}
    for _, configs, _ in fetch_results:
        for config in configs:
            seen.setdefault(serverid(config), config)
    return list(seen.values())
