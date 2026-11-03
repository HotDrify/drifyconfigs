import asyncio
import os
import time

from check import check_all
from config import NAME, SOURCES, SUB
from fetch import deduplicate, fetchall
from parser import rename


def save(alive_map: dict) -> int:
    ordered = sorted(alive_map, key=alive_map.get)
    renamed = {
        config: rename(config, f"{NAME}_{i}")
        for i, config in enumerate(ordered, 1)
    }

    os.makedirs(SUB, exist_ok=True)
    with open(
        os.path.join(SUB, "sub.txt"), "w", encoding="utf-8"
    ) as f:
        f.write("\n".join(renamed[c] for c in ordered))

    return len(ordered)


async def main():
    started = time.time()
    fetch_results = await fetchall()

    ok_sources = sum(1 for _, _, s in fetch_results if s == "ok")
    raw_total = sum(len(c) for _, c, _ in fetch_results)
    print(
        f"Fetched: {ok_sources}/{len(SOURCES)} ok | raw: {raw_total}",
        flush=True,
    )

    dedup = deduplicate(fetch_results)
    print(f"de-duplicate: {len(dedup)}", flush=True)

    alive_map = await check_all(dedup)
    percent = 100 * len(alive_map) // max(1, len(dedup))
    print(
        f"alive: {len(alive_map)}/{len(dedup)} ({percent}%)",
        flush=True,
    )

    total = save(alive_map)
    print(
        f"sub.txt: {total} configs in {time.time() - started:.1f}s",
        flush=True,
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped", flush=True)
    except Exception:
        import traceback
        traceback.print_exc()

