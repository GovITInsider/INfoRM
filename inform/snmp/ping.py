"""Async ICMP ping via /usr/bin/ping (same binary as inform-monitor)."""

from __future__ import annotations

import asyncio
import re
import shutil

_RTT_RE = re.compile(r"time[=<]([\d.]+)\s*ms")


async def ping_one(
    ip: str,
    timeout_s: int,
    sem: asyncio.Semaphore,
) -> tuple[bool, float | None]:
    ping_cmd = shutil.which("ping") or "/usr/bin/ping"
    timeout_s = int(timeout_s)
    async with sem:
        proc = await asyncio.create_subprocess_exec(
            ping_cmd,
            "-c",
            "1",
            "-W",
            str(timeout_s),
            "-n",
            ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout_s + 1
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return False, None
            if proc.returncode != 0:
                return False, None
            match = _RTT_RE.search(stdout.decode(errors="replace"))
            rtt = float(match.group(1)) if match else None
            return True, rtt
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
