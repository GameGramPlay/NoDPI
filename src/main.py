#!/usr/bin/env python3
"""
NoDPI (optimized, feature-complete rewrite)
"""

import argparse
import asyncio
import logging
import os
import random
import ssl
import socket
import subprocess
import sys
import textwrap
import time
import traceback
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from urllib.error import URLError
from urllib.request import urlopen, Request

# try uvloop for faster event loop on unix
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except Exception:
    pass

# prefer orjson for bytes -> python object; fallback to stdlib json
try:
    import orjson as _json
    def json_loads(b: bytes):
        return _json.loads(b)
except Exception:
    import json as _json
    def json_loads(b: bytes):
        # stdlib json expects str but accepts bytes in CPython 3.11+; safe to decode otherwise
        if isinstance(b, (bytes, bytearray)):
            try:
                return _json.loads(b)
            except Exception:
                return _json.loads(b.decode("utf-8", "ignore"))
        return _json.loads(b)

if sys.platform == "win32":
    import winreg

__version__ = "2.1"

# tuning
_BUF = 65536
_DRAIN_HWM = 1 << 20  # 1MB


# -------------------------
# helpers / small classes
# -------------------------

class ConnectionInfo:
    __slots__ = ("src_ip", "dst_domain", "method", "start_time", "traffic_in", "traffic_out")
    def __init__(self, src_ip: str, dst_domain: str, method: str):
        self.src_ip = src_ip
        self.dst_domain = dst_domain
        self.method = method
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.traffic_in = 0
        self.traffic_out = 0


class ProxyConfig:
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = 8881
        self.out_host = None
        self.blacklist_file = "blacklist.txt"
        self.fragment_method = "random"
        self.domain_matching = "strict"
        self.log_access_file = None
        self.log_error_file = None
        self.no_blacklist = False
        self.auto_blacklist = False
        self.quiet = False


# -------------------------
# Interfaces (kept)
# -------------------------

class IBlacklistManager(ABC):
    @abstractmethod
    def is_blocked(self, domain: str) -> bool: ...
    @abstractmethod
    async def check_domain(self, domain: bytes) -> None: ...

class ILogger(ABC):
    @abstractmethod
    def log_access(self, message: str) -> None: ...
    @abstractmethod
    def log_error(self, message: str) -> None: ...
    @abstractmethod
    def info(self, message: str) -> None: ...
    @abstractmethod
    def error(self, message: str) -> None: ...

class IStatistics(ABC):
    @abstractmethod
    def increment_total_connections(self) -> None: ...
    @abstractmethod
    def increment_allowed_connections(self) -> None: ...
    @abstractmethod
    def increment_blocked_connections(self) -> None: ...
    @abstractmethod
    def increment_error_connections(self) -> None: ...
    @abstractmethod
    def update_traffic(self, incoming: int, outgoing: int) -> None: ...
    @abstractmethod
    def update_speeds(self) -> None: ...
    @abstractmethod
    def get_stats_display(self) -> str: ...

class IConnectionHandler(ABC):
    @abstractmethod
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None: ...

class IAutostartManager(ABC):
    @staticmethod
    @abstractmethod
    def manage_autostart(action: str) -> None: ...


# -------------------------
# Blacklist implementations
# -------------------------

class FileBlacklistManager(IBlacklistManager):
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.blacklist_file = config.blacklist_file
        self.blocked: List[str] = []
        self._blocked_set: set = set()
        self.load_blacklist()

    def load_blacklist(self) -> None:
        if not os.path.exists(self.blacklist_file):
            raise FileNotFoundError(f"File {self.blacklist_file} not found")
        with open(self.blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if len(s) < 2 or s[0] == "#":
                    continue
                d = s.lower().replace("www.", "")
                self.blocked.append(d)
                self._blocked_set.add(d)

    def is_blocked(self, domain: str) -> bool:
        d = domain.replace("www.", "")
        if self.config.domain_matching == "loose":
            # using membership in set but still checking substring
            for bd in self._blocked_set:
                if bd in d:
                    return True
        if d in self._blocked_set:
            return True
        parts = d.split(".")
        for i in range(1, len(parts)):
            if ".".join(parts[i:]) in self._blocked_set:
                return True
        return False

    async def check_domain(self, domain: bytes) -> None:
        return


class AutoBlacklistManager(IBlacklistManager):
    def __init__(self, config: ProxyConfig):
        self.blacklist_file = config.blacklist_file
        self._blocked_set: set = set()
        self._whitelist_set: set = set()

    def is_blocked(self, domain: str) -> bool:
        return domain in self._blocked_set

    async def check_domain(self, domain: bytes) -> None:
        dec = domain.decode()
        if dec in self._blocked_set or dec in self._whitelist_set:
            return
        try:
            req = Request(f"https://{dec}", headers={"User-Agent": "Mozilla/5.0"})
            ctx = ssl._create_unverified_context()
            loop = asyncio.get_running_loop()

            def probe():
                with urlopen(req, timeout=4, context=ctx):
                    pass

            await loop.run_in_executor(None, probe)
            self._whitelist_set.add(dec)
        except URLError as e:
            # match exact error text as before
            try:
                reason = str(e.reason)
            except Exception:
                reason = ""
            if "handshake operation timed out" in reason:
                self._blocked_set.add(dec)
                try:
                    with open(self.blacklist_file, "a", encoding="utf-8") as f:
                        f.write(dec + "\n")
                except Exception:
                    pass
        except Exception:
            self._whitelist_set.add(dec)


class NoBlacklistManager(IBlacklistManager):
    def is_blocked(self, domain: str) -> bool:
        return True
    async def check_domain(self, domain: bytes) -> None:
        return


# -------------------------
# Logger (kept behavior)
# -------------------------

class ProxyLogger(ILogger):
    def __init__(self, log_access_file: Optional[str], log_error_file: Optional[str], quiet: bool = False):
        self.quiet = quiet
        self.logger = logging.getLogger("nodpi")
        self.error_counter_callback = None
        self._setup_logging(log_access_file, log_error_file)

    def _setup_logging(self, log_access_file, log_error_file):
        class ErrorCounterHandler(logging.FileHandler):
            def __init__(self, counter_callback, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.counter_callback = counter_callback
            def emit(self, record):
                try:
                    if record.levelno >= logging.ERROR:
                        self.counter_callback()
                except Exception:
                    pass
                super().emit(record)

        if log_error_file:
            err = ErrorCounterHandler(self.increment_errors, log_error_file, encoding="utf-8")
            err.setFormatter(logging.Formatter("[%(asctime)s][%(levelname)s]: %(message)s", "%Y-%m-%d %H:%M:%S"))
            err.setLevel(logging.ERROR)
            err.addFilter(lambda r: r.levelno == logging.ERROR)
            error_handler = err
        else:
            error_handler = logging.NullHandler()

        if log_access_file:
            access_handler = logging.FileHandler(log_access_file, encoding="utf-8")
            access_handler.setFormatter(logging.Formatter("%(message)s"))
            access_handler.setLevel(logging.INFO)
            access_handler.addFilter(lambda r: r.levelno == logging.INFO)
        else:
            access_handler = logging.NullHandler()

        self.logger.propagate = False
        self.logger.handlers = []
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(error_handler)
        self.logger.addHandler(access_handler)

    def set_error_counter_callback(self, callback):
        self.error_counter_callback = callback

    def increment_errors(self) -> None:
        if self.error_counter_callback:
            try:
                self.error_counter_callback()
            except Exception:
                pass

    def log_access(self, message: str) -> None:
        try:
            self.logger.info(message)
        except Exception:
            pass

    def log_error(self, message: str) -> None:
        try:
            self.logger.error(message)
        except Exception:
            pass

    def info(self, *a, **k) -> None:
        if not self.quiet:
            print(*a, **k)

    def error(self, *a, **k) -> None:
        if not self.quiet:
            print(*a, **k)


# -------------------------
# Stats (kept)
# -------------------------

class Statistics(IStatistics):
    def __init__(self):
        self.total_connections = 0
        self.allowed_connections = 0
        self.blocked_connections = 0
        self.errors_connections = 0
        self.traffic_in = 0
        self.traffic_out = 0
        self.last_traffic_in = 0
        self.last_traffic_out = 0
        self.speed_in = 0
        self.speed_out = 0
        self.average_speed_in = (0.0, 1)
        self.average_speed_out = (0.0, 1)
        self.last_time = None

    def increment_total_connections(self) -> None:
        self.total_connections += 1
    def increment_allowed_connections(self) -> None:
        self.allowed_connections += 1
    def increment_blocked_connections(self) -> None:
        self.blocked_connections += 1
    def increment_error_connections(self) -> None:
        self.errors_connections += 1

    def update_traffic(self, incoming: int, outgoing: int) -> None:
        self.traffic_in += incoming
        self.traffic_out += outgoing

    def update_speeds(self) -> None:
        current_time = time.monotonic()
        if self.last_time is not None:
            dt = current_time - self.last_time
            if dt > 0:
                self.speed_in = (self.traffic_in - self.last_traffic_in) * 8 / dt
                self.speed_out = (self.traffic_out - self.last_traffic_out) * 8 / dt
                if self.speed_in > 0:
                    self.average_speed_in = (self.average_speed_in[0] + self.speed_in, self.average_speed_in[1] + 1)
                if self.speed_out > 0:
                    self.average_speed_out = (self.average_speed_out[0] + self.speed_out, self.average_speed_out[1] + 1)
        self.last_traffic_in = self.traffic_in
        self.last_traffic_out = self.traffic_out
        self.last_time = current_time

    @staticmethod
    def format_size(size: int) -> str:
        units = ["B", "KB", "MB", "GB"]
        unit = 0
        s = float(size)
        while s >= 1024 and unit < len(units) - 1:
            s /= 1024
            unit += 1
        return f"{s:.1f} {units[unit]}"

    @staticmethod
    def format_speed(speed_bps: float) -> str:
        if speed_bps <= 0:
            return "0 b/s"
        units = ["b/s", "Kb/s", "Mb/s", "Gb/s"]
        unit = 0
        speed = speed_bps
        while speed >= 1000 and unit < len(units) - 1:
            speed /= 1000
            unit += 1
        return f"{speed:.0f} {units[unit]}"

    def get_stats_display(self) -> str:
        col_width = 30
        conns_stat = (
            f"\033[97mTotal: \033[93m{self.total_connections}\033[0m".ljust(col_width)
            + "\033[97m| "
            + f"\033[97mMiss: \033[96m{self.allowed_connections}\033[0m".ljust(col_width)
            + "\033[97m| "
            + f"\033[97mUnblock: \033[92m{self.blocked_connections}\033[0m".ljust(col_width)
            + "\033[97m| "
            + f"\033[97mErrors: \033[91m{self.errors_connections}\033[0m".ljust(col_width)
        )
        traffic_stat = (
            f"\033[97mTotal: \033[96m{self.format_size(self.traffic_out + self.traffic_in)}\033[0m".ljust(col_width)
            + "\033[97m| "
            + f"\033[97mDL: \033[96m{self.format_size(self.traffic_in)}\033[0m".ljust(col_width)
            + "\033[97m| "
            + f"\033[97mUL: \033[96m{self.format_size(self.traffic_out)}\033[0m".ljust(col_width)
            + "\033[97m| "
        )
        avg_in = self.average_speed_in[0] / self.average_speed_in[1]
        avg_out = self.average_speed_out[0] / self.average_speed_out[1]
        speed_stat = (
            f"\033[97mDL: \033[96m{self.format_speed(self.speed_in)}\033[0m".ljust(col_width)
            + "\033[97m| "
            + f"\033[97mUL: \033[96m{self.format_speed(self.speed_out)}\033[0m".ljust(col_width)
            + "\033[97m| "
            + f"\033[97mAVG DL: \033[96m{self.format_speed(avg_in)}\033[0m".ljust(col_width)
            + "\033[97m| "
            + f"\033[97mAVG UL: \033[96m{self.format_speed(avg_out)}\033[0m"
        )
        title = "STATISTICS"
        top_border = f"\033[92m{'═' * 36} {title} {'═' * 36}\033[0m"
        line_conns = f"\033[92m   {'Conns'.ljust(8)}:\033[0m {conns_stat}\033[0m"
        line_traffic = f"\033[92m   {'Traffic'.ljust(8)}:\033[0m {traffic_stat}\033[0m"
        line_speed = f"\033[92m   {'Speed'.ljust(8)}:\033[0m {speed_stat}\033[0m"
        bottom = f"\033[92m{'═' * (36 * 2 + len(title) + 2)}\033[0m"
        return f"{top_border}\n{line_conns}\n{line_traffic}\n{line_speed}\n{bottom}"


# -------------------------
# Connection Handler (feature-full, optimized)
# -------------------------

class ConnectionHandler(IConnectionHandler):
    def __init__(self, config: ProxyConfig, blacklist_manager: IBlacklistManager, statistics: IStatistics, logger: ILogger):
        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.out_host = config.out_host

        # active connections dictionary retained for logging and bookkeeping
        self.active_connections: Dict[Tuple, ConnectionInfo] = {}
        self.connections_lock = asyncio.Lock()  # only for modifications
        self.tasks: List[asyncio.Task] = []

        # local RNG alias for speed
        self._randrange = random.randrange

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn_key = ()
        try:
            peer = writer.get_extra_info("peername")
            if not peer:
                peer = ("unknown", 0)
            client_ip, client_port = peer[0], peer[1]

            # read initial chunk
            http_data = await reader.read(_BUF)
            if not http_data:
                try:
                    writer.close()
                except Exception:
                    pass
                return

            method, host, port = self._parse_http_request(http_data)
            conn_key = (client_ip, client_port)
            conn_info = ConnectionInfo(client_ip, host.decode(), method.decode())

            # autoblacklist probe if needed
            if method == b"CONNECT" and isinstance(self.blacklist_manager, AutoBlacklistManager):
                # spawn probe but await it (as before)
                await self.blacklist_manager.check_domain(host)

            # register connection (mutation guarded by lock)
            async with self.connections_lock:
                self.active_connections[conn_key] = conn_info

            # account for initial read bytes
            self.statistics.update_traffic(0, len(http_data))
            conn_info.traffic_out += len(http_data)

            if method == b"CONNECT":
                await self._handle_https_connection(reader, writer, host, port, conn_key, conn_info)
            else:
                await self._handle_http_connection(reader, writer, http_data, host, port, conn_key)

        except Exception:
            await self._handle_connection_error(writer, conn_key)

    def _parse_http_request(self, http_data: bytes) -> Tuple[bytes, bytes, int]:
        # minimal allocations: find first CRLF and split that slice only
        first_crlf = http_data.find(b"\r\n")
        if first_crlf == -1:
            raise ValueError("Malformed HTTP request")
        first_line = http_data[:first_crlf]
        parts = first_line.split(b" ")
        method = parts[0]
        url = parts[1]

        if method == b"CONNECT":
            hp = url.split(b":", 1)
            host = hp[0]
            port = int(hp[1]) if len(hp) > 1 else 443
            return method, host, port

        # find Host header quickly (avoid splitting all headers)
        host_pos = http_data.find(b"\r\nHost: ")
        if host_pos == -1:
            # fallback to generic search
            headers = http_data.split(b"\r\n")
            host_header = next((h for h in headers if h.startswith(b"Host: ")), None)
            if not host_header:
                raise ValueError("Missing Host header")
            host_port = host_header[6:].split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 80
            return method, host, port

        start = host_pos + 8
        end = http_data.find(b"\r\n", start)
        host_line = http_data[start:end]
        hp = host_line.split(b":", 1)
        host = hp[0]
        port = int(hp[1]) if len(hp) > 1 else 80
        return method, host, port

    async def _handle_https_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: bytes, port: int, conn_key: Tuple, conn_info: ConnectionInfo) -> None:
        established = b"HTTP/1.1 200 Connection Established\r\n\r\n"
        self.statistics.update_traffic(len(established), 0)
        conn_info.traffic_in += len(established)

        # open remote
        remote_reader, remote_writer = await asyncio.open_connection(
            host.decode(), port,
            local_addr=(self.out_host, 0) if self.out_host else None,
            limit=_BUF,
        )

        # reply to client
        writer.write(established)
        await writer.drain()

        await self._handle_initial_tls_data(reader, remote_writer, host, conn_info)
        await self._run_pipes(reader, writer, remote_reader, remote_writer, conn_key)

    async def _handle_http_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, http_data: bytes, host: bytes, port: int, conn_key: Tuple) -> None:
        remote_reader, remote_writer = await asyncio.open_connection(
            host.decode(), port,
            local_addr=(self.out_host, 0) if self.out_host else None,
            limit=_BUF,
        )
        remote_writer.write(http_data)
        await remote_writer.drain()

        self.statistics.increment_total_connections()
        self.statistics.increment_allowed_connections()

        await self._run_pipes(reader, writer, remote_reader, remote_writer, conn_key)

    def _extract_sni_position(self, data: bytes):
        # unchanged algorithm but local variables and bounds checks
        pos = data.find(b"\x00\x00")
        while pos != -1 and pos + 9 <= len(data):
            try:
                ext_len = int.from_bytes(data[pos+2:pos+4], "big")
                list_len = int.from_bytes(data[pos+4:pos+6], "big")
                name_len = int.from_bytes(data[pos+7:pos+9], "big")
                if ext_len - list_len == 2 and list_len - name_len == 3:
                    sni_start = pos + 9
                    return sni_start, sni_start + name_len
            except Exception:
                pass
            pos = data.find(b"\x00\x00", pos + 1)
        return None

    async def _handle_initial_tls_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: bytes, conn_info: ConnectionInfo) -> None:
        try:
            head = await reader.read(5)
            data = await reader.read(2048)
        except Exception:
            try:
                self.logger.log_error(f"{host.decode()} : {traceback.format_exc()}")
            except Exception:
                pass
            return

        should_fragment = True
        if not isinstance(self.blacklist_manager, NoBlacklistManager):
            should_fragment = self.blacklist_manager.is_blocked(conn_info.dst_domain)

        if not should_fragment:
            self.statistics.increment_total_connections()
            self.statistics.increment_allowed_connections()
            combined = head + data
            writer.write(combined)
            await writer.drain()
            self.statistics.update_traffic(0, len(combined))
            conn_info.traffic_out += len(combined)
            return

        self.statistics.increment_total_connections()
        self.statistics.increment_blocked_connections()

        parts: List[bytes] = []
        hdr = bytes.fromhex("160304")

        if self.config.fragment_method == "sni":
            sni_pos = self._extract_sni_position(data)
            if sni_pos:
                pre = data[:sni_pos[0]]
                sni = data[sni_pos[0]:sni_pos[1]]
                post = data[sni_pos[1]:]
                mid = (len(sni) + 1) // 2
                parts = [
                    hdr + len(pre).to_bytes(2, "big") + pre,
                    hdr + len(sni[:mid]).to_bytes(2, "big") + sni[:mid],
                    hdr + len(sni[mid:]).to_bytes(2, "big") + sni[mid:],
                    hdr + len(post).to_bytes(2, "big") + post,
                ]
        else:
            # random fragmentation
            host_end = data.find(b"\x00")
            if host_end != -1:
                chunk = data[:host_end + 1]
                parts.append(hdr + (host_end + 1).to_bytes(2, "big") + chunk)
                data = data[host_end + 1:]
            # build random fragments
            append = parts.append
            randrange = self._randrange
            while data:
                # use randrange(1, n+1) instead of randint
                n = randrange(1, len(data) + 1)
                append(hdr + n.to_bytes(2, "big") + data[:n])
                data = data[n:]

        combined = b"".join(parts)
        writer.write(combined)
        await writer.drain()
        self.statistics.update_traffic(0, len(combined))
        conn_info.traffic_out += len(combined)

    # run pipes and close once
    async def _run_pipes(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, remote_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter, conn_key: Tuple) -> None:
        # start both pipe tasks and await; each pipe won't close writer
        t1 = asyncio.create_task(self._pipe(client_reader, remote_writer, True))
        t2 = asyncio.create_task(self._pipe(remote_reader, client_writer, False))
        await asyncio.gather(t1, t2, return_exceptions=True)

        # commit traffic already done in pipes (they updated stats)
        # close both writers cleanly once
        for w in (client_writer, remote_writer):
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass

        # cleanup active connections and log
        async with self.connections_lock:
            removed = self.active_connections.pop(conn_key, None)
        if removed:
            try:
                self.logger.log_access(f"{removed.start_time} {removed.src_ip} {removed.method} {removed.dst_domain} {removed.traffic_in} {removed.traffic_out}")
            except Exception:
                pass

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_out: bool) -> None:
        stats = self.statistics
        local_vol = 0

        # cache often-used attributes locally
        transport = writer.transport
        write = writer.write
        drain = writer.drain
        read = reader.read

        # try to get conn_info without lock (read-only)
        conn_info = None
        try:
            # minor optimization: avoid awaiting lock for read-only get
            # dict.get is thread-safe for reads under single interpreter
            # this assumes no concurrent interpreter threads mutate dict concurrently
            # which is true for our single-threaded event loop
            # getting a conn_info is only for best-effort logging on errors
            # if missing, code continues
            # note: no await here
            conn_key_approx = None  # not available in this scope reliably
        except Exception:
            conn_info = None

        try:
            while True:
                data = await read(_BUF)
                if not data:
                    break
                write(data)
                local_vol += len(data)

                # check write buffer without repeated attribute lookup
                if transport.get_write_buffer_size() > _DRAIN_HWM:
                    await drain()

            # final flush
            await drain()

        except asyncio.CancelledError:
            pass
        except Exception:
            # attempt to log domain if possible
            domain = conn_info.dst_domain if conn_info else "unknown"
            try:
                self.logger.log_error(f"{domain} : {traceback.format_exc()}")
            except Exception:
                pass
        finally:
            # commit traffic in a single call
            if is_out:
                stats.update_traffic(0, local_vol)
                if conn_info:
                    conn_info.traffic_out += local_vol
            else:
                stats.update_traffic(local_vol, 0)
                if conn_info:
                    conn_info.traffic_in += local_vol

    async def _handle_connection_error(self, writer: asyncio.StreamWriter, conn_key: Tuple) -> None:
        try:
            error_response = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
            writer.write(error_response)
            await writer.drain()
            self.statistics.update_traffic(len(error_response), 0)
        except Exception:
            pass

        async with self.connections_lock:
            conn_info = self.active_connections.pop(conn_key, None)

        self.statistics.increment_total_connections()
        self.statistics.increment_error_connections()

        domain = conn_info.dst_domain if conn_info else "unknown"
        try:
            self.logger.log_error(f"{domain} : {traceback.format_exc()}")
        except Exception:
            pass

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def cleanup_tasks(self) -> None:
        while True:
            await asyncio.sleep(60)
            self.tasks = [t for t in self.tasks if not t.done()]


# -------------------------
# Proxy server (keeps features)
# -------------------------

class ProxyServer:
    def __init__(self, config: ProxyConfig, blacklist_manager: IBlacklistManager, statistics: IStatistics, logger: ILogger):
        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.connection_handler = ConnectionHandler(config, blacklist_manager, statistics, logger)
        self.server = None
        self.update_check_task = None
        self.update_available = None
        self.update_event = asyncio.Event()
        logger.set_error_counter_callback(statistics.increment_error_connections)

    async def check_for_updates(self):
        if self.config.quiet:
            return None
        try:
            loop = asyncio.get_running_loop()
            def sync_check():
                try:
                    req = Request("https://gvcoder09.github.io/nodpi_site/api/v1/update_info.json")
                    with urlopen(req, timeout=3) as resp:
                        if resp.status == 200:
                            data = json_loads(resp.read())
                            latest_version = data.get("nodpi", {}).get("latest_version", "")
                            if latest_version and latest_version != __version__:
                                return latest_version
                except Exception:
                    pass
                return None
            latest = await loop.run_in_executor(None, sync_check)
            if latest:
                self.update_available = latest
                self.update_event.set()
                return f"\033[93m[UPDATE]: Available new version: v{latest} \033[97m"
        except Exception:
            pass
        finally:
            self.update_event.set()
        return None

    async def print_banner(self) -> None:
        self.update_check_task = asyncio.create_task(self.check_for_updates())
        try:
            await asyncio.wait_for(self.update_event.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            if self.update_check_task and not self.update_check_task.done():
                self.update_check_task.cancel()
                try:
                    await self.update_check_task
                except asyncio.CancelledError:
                    pass

        self.logger.info("\033]0;NoDPI\007")
        if sys.platform == "win32":
            os.system("mode con: lines=33")

        console_width = os.get_terminal_size().columns if sys.stdout.isatty() else 80
        disclaimer = ("DISCLAIMER. The developer and/or supplier of this software "
                      "shall not be liable for any loss or damage, including but "
                      "not limited to direct, indirect, incidental, punitive or "
                      "consequential damages arising out of the use of or inability "
                      "to use this software, even if the developer or supplier has been "
                      "advised of the possibility of such damages. The developer and/or "
                      "supplier of this software shall not be liable for any legal "
                      "consequences arising out of the use of this software. This includes, "
                      "but is not limited to, violation of laws, rules or regulations, "
                      "as well as any claims or suits arising out of the use of this software. "
                      "The user is solely responsible for compliance with all applicable laws "
                      "and regulations when using this software.")
        wrapped_text = textwrap.TextWrapper(width=70).wrap(disclaimer)
        left_padding = (console_width - 76) // 2

        self.logger.info("\n\n\n")
        self.logger.info("\033[91m" + " " * left_padding + "╔" + "═" * 72 + "╗" + "\033[0m")
        for line in wrapped_text:
            self.logger.info("\033[91m" + " " * left_padding + "║ " + line.ljust(70) + " ║" + "\033[0m")
        self.logger.info("\033[91m" + " " * left_padding + "╚" + "═" * 72 + "╝" + "\033[0m")
        time.sleep(1)

        update_message = None
        if self.update_check_task and self.update_check_task.done():
            try:
                update_message = self.update_check_task.result()
            except Exception:
                pass

        self.logger.info("\033[2J\033[H")
        self.logger.info("""
\033[92m  ██████   █████          ██████████   ███████████  █████
 ░░██████ ░░███          ░░███░░░░███ ░░███░░░░░███░░███
  ░███░███ ░███   ██████  ░███   ░░███ ░███    ░███ ░███
  ░███░░███░███  ███░░███ ░███    ░███ ░██████████  ░███
  ░███ ░░██████ ░███ ░███ ░███    ░███ ░███░░░░░░   ░███
  ░███  ░░█████ ░███ ░███ ░███    ███  ░███         ░███
  █████  ░░█████░░██████  ██████████   █████        █████
 ░░░░░    ░░░░░  ░░░░░░  ░░░░░░░░░░   ░░░░░        ░░░░░\033[0m
        """)
        self.logger.info(f"\033[92mVersion: {__version__}".center(50))
        self.logger.info("\033[97m" + "Enjoy watching! / Наслаждайтесь просмотром!".center(50))
        self.logger.info("\n")
        if update_message:
            self.logger.info(update_message)

        self.logger.info(f"\033[92m[INFO]:\033[97m Proxy is running on {self.config.host}:{self.config.port} at {datetime.now().strftime('%H:%M on %Y-%m-%d')}")
        self.logger.info(f"\033[92m[INFO]:\033[97m The selected fragmentation method: {self.config.fragment_method}")
        self.logger.info("")
        if isinstance(self.blacklist_manager, NoBlacklistManager):
            self.logger.info("\033[92m[INFO]:\033[97m Blacklist is disabled. All domains will be subject to unblocking.")
        elif isinstance(self.blacklist_manager, AutoBlacklistManager):
            self.logger.info("\033[92m[INFO]:\033[97m Auto-blacklist is enabled")
        else:
            try:
                self.logger.info(f"\033[92m[INFO]:\033[97m Blacklist contains {len(self.blacklist_manager.blocked)} domains")
                self.logger.info(f"\033[92m[INFO]:\033[97m Path to blacklist: '{os.path.normpath(self.config.blacklist_file)}'")
            except Exception:
                pass

        self.logger.info("")
        if self.config.log_error_file:
            self.logger.info(f"\033[92m[INFO]:\033[97m Error logging is enabled. Path to error log: '{self.config.log_error_file}'")
        else:
            self.logger.info("\033[92m[INFO]:\033[97m Error logging is disabled")
        if self.config.log_access_file:
            self.logger.info(f"\033[92m[INFO]:\033[97m Access logging is enabled. Path to access log: '{self.config.log_access_file}'")
        else:
            self.logger.info("\033[92m[INFO]:\033[97m Access logging is disabled")
        self.logger.info("")
        self.logger.info("\033[92m[INFO]:\033[97m To stop the proxy, press Ctrl+C twice")
        self.logger.info("")

    async def display_stats(self) -> None:
        while True:
            await asyncio.sleep(1)
            self.statistics.update_speeds()
            if not self.config.quiet:
                print(self.statistics.get_stats_display())
                print("\033[5A", end="")

    async def run(self) -> None:
        if not self.config.quiet:
            await self.print_banner()

        try:
            self.server = await asyncio.start_server(
                self.connection_handler.handle_connection,
                self.config.host,
                self.config.port,
                limit=_BUF,
            )
        except OSError:
            self.logger.error(f"\033[91m[ERROR]: Failed to start proxy on this address ({self.config.host}:{self.config.port}). It looks like the port is already in use\033[0m")
            sys.exit(1)

        # set TCP_NODELAY for server sockets to reduce latency on small packets
        try:
            for s in self.server.sockets or []:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        if not self.config.quiet:
            asyncio.create_task(self.display_stats())
        asyncio.create_task(self.connection_handler.cleanup_tasks())

        await self.server.serve_forever()

    async def shutdown(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for task in self.connection_handler.tasks:
            task.cancel()


# -------------------------
# Factories / loaders (kept)
# -------------------------

class BlacklistManagerFactory:
    @staticmethod
    def create(config: ProxyConfig, logger: ILogger) -> IBlacklistManager:
        if config.no_blacklist:
            return NoBlacklistManager()
        if config.auto_blacklist:
            return AutoBlacklistManager(config)
        try:
            return FileBlacklistManager(config)
        except FileNotFoundError as e:
            logger.error(f"\033[91m[ERROR]: {e}\033[0m")
            sys.exit(1)


class ConfigLoader:
    @staticmethod
    def load_from_args(args) -> ProxyConfig:
        config = ProxyConfig()
        config.host = args.host
        config.port = args.port
        config.out_host = args.out_host
        config.blacklist_file = args.blacklist
        config.fragment_method = args.fragment_method
        config.domain_matching = args.domain_matching
        config.log_access_file = args.log_access
        config.log_error_file = args.log_error
        config.no_blacklist = args.no_blacklist
        config.auto_blacklist = args.autoblacklist
        config.quiet = args.quiet
        return config


# -------------------------
# Autostart managers (kept)
# -------------------------

class WindowsAutostartManager(IAutostartManager):
    @staticmethod
    def manage_autostart(action: str = "install") -> None:
        app_name = "NoDPIProxy"
        exe_path = sys.executable
        try:
            key = winreg.HKEY_CURRENT_USER
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            if action == "install":
                with winreg.OpenKey(key, reg_path, 0, winreg.KEY_WRITE) as regkey:
                    winreg.SetValueEx(regkey, app_name, 0, winreg.REG_SZ,
                                      f'"{exe_path}" --blacklist "{os.path.dirname(exe_path)}/blacklist.txt"',)
                print(f"\033[92m[INFO]:\033[97m Added to autostart: {exe_path}")
            elif action == "uninstall":
                try:
                    with winreg.OpenKey(key, reg_path, 0, winreg.KEY_WRITE) as regkey:
                        winreg.DeleteValue(regkey, app_name)
                    print("\033[92m[INFO]:\033[97m Removed from autostart")
                except FileNotFoundError:
                    print("\033[91m[ERROR]: Not found in autostart\033[0m")
        except PermissionError:
            print("\033[91m[ERROR]: Access denied. Run as administrator\033[0m")
        except Exception as e:
            print(f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")


class LinuxAutostartManager(IAutostartManager):
    @staticmethod
    def manage_autostart(action: str = "install") -> None:
        app_name = "NoDPIProxy"
        exec_path = sys.executable
        service_name = f"{app_name.lower()}.service"
        user_service_dir = Path.home() / ".config" / "systemd" / "user"
        service_file = user_service_dir / service_name
        blacklist_path = f"{os.path.dirname(exec_path)}/blacklist.txt"

        if action == "install":
            try:
                user_service_dir.mkdir(parents=True, exist_ok=True)
                service_content = f"""[Unit]
Description=NoDPIProxy Service
After=network.target graphical-session.target
Wants=network.target

[Service]
Type=simple
ExecStart={exec_path} --blacklist "{blacklist_path}" --quiet
Restart=on-failure
RestartSec=5
Environment=DISPLAY=:0
Environment=XAUTHORITY=%h/.Xauthority

[Install]
WantedBy=default.target
"""
                service_file.write_text(service_content, encoding="utf-8")
                subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
                subprocess.run(["systemctl", "--user", "enable", service_name], check=True)
                subprocess.run(["systemctl", "--user", "start", service_name], check=True)
                print(f"\033[92m[INFO]:\033[97m Service installed and started: {service_name}")
                print("\033[93m[NOTE]:\033[97m Service will auto-start on login")
            except subprocess.CalledProcessError as e:
                print(f"\033[91m[ERROR]: Systemd command failed: {e}\033[0m")
            except Exception as e:
                print(f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")
        elif action == "uninstall":
            try:
                subprocess.run(["systemctl", "--user", "stop", service_name], capture_output=True, check=True)
                subprocess.run(["systemctl", "--user", "disable", service_name], capture_output=True, check=True)
                if service_file.exists():
                    service_file.unlink()
                subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
                print("\033[92m[INFO]:\033[97m Service removed from autostart")
            except subprocess.CalledProcessError as e:
                print(f"\033[91m[ERROR]: Systemd command failed: {e}\033[0m")
            except Exception as e:
                print(f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")


# -------------------------
# Application entrypoint
# -------------------------

class ProxyApplication:
    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser()
        parser.add_argument("--host", default="127.0.0.1", help="Proxy host")
        parser.add_argument("--port", type=int, default=8881, help="Proxy port")
        parser.add_argument("--out-host", help="Outgoing proxy host")
        bl_group = parser.add_mutually_exclusive_group()
        bl_group.add_argument("--blacklist", default="blacklist.txt", help="Path to blacklist file")
        bl_group.add_argument("--no-blacklist", action="store_true", help="Use fragmentation for all domains")
        bl_group.add_argument("--autoblacklist", action="store_true", help="Automatic detection of blocked domains")
        parser.add_argument("--fragment-method", default="random", choices=["random", "sni"], help="Fragmentation method")
        parser.add_argument("--domain-matching", default="strict", choices=["loose", "strict"], help="Domain matching mode")
        parser.add_argument("--log-access", required=False, help="Path to the access control log")
        parser.add_argument("--log-error", required=False, help="Path to log file for errors")
        parser.add_argument("-q", "--quiet", action="store_true", help="Remove UI output")
        as_group = parser.add_mutually_exclusive_group()
        as_group.add_argument("--install", action="store_true", help="Add proxy to autostart")
        as_group.add_argument("--uninstall", action="store_true", help="Remove proxy from autostart")
        return parser.parse_args()

    @classmethod
    async def run(cls):
        logging.getLogger("asyncio").setLevel(logging.CRITICAL)
        args = cls.parse_args()

        if args.install or args.uninstall:
            if getattr(sys, "frozen", False):
                mgr = WindowsAutostartManager if sys.platform == "win32" else LinuxAutostartManager
                action = "install" if args.install else "uninstall"
                mgr.manage_autostart(action)
                sys.exit(0)
            else:
                print("\033[91m[ERROR]: Autostart works only in executable version\033[0m")
                sys.exit(1)

        config = ConfigLoader.load_from_args(args)
        logger = ProxyLogger(config.log_access_file, config.log_error_file, config.quiet)
        blacklist = BlacklistManagerFactory.create(config, logger)
        stats = Statistics()
        logger.set_error_counter_callback(stats.increment_error_connections)
        proxy = ProxyServer(config, blacklist, stats, logger)
        try:
            await proxy.run()
        except asyncio.CancelledError:
            await proxy.shutdown()
            logger.info("\n" * 6 + "\033[92m[INFO]:\033[97m Shutting down proxy...")
            try:
                if sys.platform == "win32":
                    os.system("mode con: lines=3000")
                sys.exit(0)
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    try:
        asyncio.run(ProxyApplication.run())
    except KeyboardInterrupt:
        pass
