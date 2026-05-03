import ctypes
import ctypes.wintypes
import os
import struct
import time

kernel32 = ctypes.windll.kernel32

INVALID_HANDLE = ctypes.c_void_p(-1).value
GENERIC_RW = 0x80000000 | 0x40000000
OPEN_EXISTING = 3
FILE_ATTR_NORMAL = 0x80

K_MAGIC = 0x4D505257
K_HEADER = 16
MAX_CHUNK = 16384
MAX_PATH_CHARS = 1024
STATUS_OK = 0


class IpcClient:
    def __init__(self, pid, timeout_ms=2000):
        self.pid = pid
        self.handle = self._connect(pid, timeout_ms)

    def close(self):
        if self.handle and self.handle != INVALID_HANDLE:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def is_connected(self):
        return self.handle is not None and self.handle != INVALID_HANDLE

    def read(self, address, size):
        if size <= MAX_CHUNK:
            return self._read_chunk(address, size)
        return self._read_blocks(address, size)

    def read_ptr(self, address):
        d = self.read(address, 8)
        return struct.unpack("<Q", d)[0] if d and len(d) >= 8 else None

    def read_i32(self, address):
        d = self.read(address, 4)
        return struct.unpack("<i", d)[0] if d and len(d) >= 4 else None

    def read_u32(self, address):
        d = self.read(address, 4)
        return struct.unpack("<I", d)[0] if d and len(d) >= 4 else None

    def read_u16(self, address):
        d = self.read(address, 2)
        return struct.unpack("<H", d)[0] if d and len(d) >= 2 else None

    def enum_modules(self):
        rid = int(time.time() * 1000) & 0xFFFFFFFFFFFF
        payload = struct.pack("<Q", rid)
        hdr = struct.pack("<IIII", K_MAGIC, 7, K_HEADER + len(payload), os.getpid())
        if not self._write_all(hdr + payload):
            return None
        reply_hdr = self._read_all(K_HEADER)
        if not reply_hdr:
            return None
        magic, kind, rsize, _ = struct.unpack("<IIII", reply_hdr)
        if magic != K_MAGIC or rsize < K_HEADER:
            return None
        body = self._read_all(rsize - K_HEADER) if rsize > K_HEADER else b""
        if body is None:
            return None
        return self._parse_module_reply(body)

    def load_dll(self, path):
        rid = int(time.time() * 1000) & 0xFFFFFFFFFFFF
        encoded = path.encode("utf-16-le")
        max_bytes = MAX_PATH_CHARS * 2
        if len(encoded) >= max_bytes:
            raise ValueError("DLL path is too long")
        payload = struct.pack("<Q", rid) + encoded + b"\x00\x00" + b"\x00" * (max_bytes - len(encoded) - 2)
        hdr = struct.pack("<IIII", K_MAGIC, 9, K_HEADER + len(payload), os.getpid())
        if not self._write_all(hdr + payload):
            return None
        reply_hdr = self._read_all(K_HEADER)
        if not reply_hdr:
            return None
        magic, kind, rsize, _ = struct.unpack("<IIII", reply_hdr)
        if magic != K_MAGIC or kind != 10 or rsize < K_HEADER:
            return None
        body = self._read_all(rsize - K_HEADER) if rsize > K_HEADER else b""
        if body is None:
            return None
        return self._parse_load_reply(body)

    def _connect(self, pid, timeout_ms):
        name = f"\\\\.\\pipe\\WinHttpRedirectProxyMemory-{pid}"
        if not kernel32.WaitNamedPipeW(name, timeout_ms):
            return None
        h = kernel32.CreateFileW(
            name, GENERIC_RW, 0, None, OPEN_EXISTING, FILE_ATTR_NORMAL, None
        )
        if h == INVALID_HANDLE:
            return None
        mode = ctypes.c_ulong(0)
        kernel32.SetNamedPipeHandleState(h, ctypes.byref(mode), None, None)
        return h

    def _read_blocks(self, address, size):
        chunks = []
        addr = address
        remain = size
        while remain > 0:
            cs = min(remain, MAX_CHUNK)
            d = self._read_chunk(addr, cs)
            if not d:
                return None
            chunks.append(d)
            addr += cs
            remain -= cs
        return b"".join(chunks)

    def _read_chunk(self, address, size):
        rid = int(time.time() * 1000) & 0xFFFFFFFFFFFF
        payload = struct.pack("<QQII", rid, address, size, 0)
        hdr = struct.pack("<IIII", K_MAGIC, 1, K_HEADER + len(payload), os.getpid())
        if not self._write_all(hdr + payload):
            return None
        reply_hdr = self._read_all(K_HEADER)
        if not reply_hdr:
            return None
        magic, kind, rsize, _ = struct.unpack("<IIII", reply_hdr)
        if magic != K_MAGIC or rsize < K_HEADER:
            return None
        body = self._read_all(rsize - K_HEADER) if rsize > K_HEADER else b""
        if body is None:
            return None
        return self._parse_data(body)

    def _parse_data(self, body):
        if len(body) < 96:
            return None
        status = struct.unpack_from("<I", body, 56)[0]
        dsz = struct.unpack_from("<I", body, 92)[0]
        if status != STATUS_OK:
            return None
        return body[96:96 + dsz]

    def _parse_module_reply(self, body):
        if len(body) < 16:
            return None
        status = struct.unpack_from("<I", body, 8)[0]
        if status != STATUS_OK:
            return None
        count = struct.unpack_from("<I", body, 16)[0]
        entries = []
        off = 24
        for _ in range(count):
            if off + 536 > len(body):
                break
            base = struct.unpack_from("<Q", body, off)[0]
            size = struct.unpack_from("<Q", body, off + 8)[0]
            name_raw = body[off + 16:off + 16 + 520]
            name = name_raw.decode("utf-16-le", errors="replace").split("\x00")[0]
            entries.append({"base": base, "size": size, "name": name})
            off += 536
        return entries

    def _parse_load_reply(self, body):
        min_size = 24 + MAX_PATH_CHARS * 2 * 2
        if len(body) < min_size:
            return None
        request_id, module_handle, status, win32_error = struct.unpack_from("<QQII", body, 0)
        path_raw = body[24:24 + MAX_PATH_CHARS * 2]
        text_raw = body[24 + MAX_PATH_CHARS * 2:24 + MAX_PATH_CHARS * 4]
        path = path_raw.decode("utf-16-le", errors="replace").split("\x00")[0]
        text = text_raw.decode("utf-16-le", errors="replace").split("\x00")[0]
        return {
            "request_id": request_id,
            "module": module_handle,
            "status": status,
            "win32_error": win32_error,
            "path": path,
            "text": text,
        }

    def _read_all(self, size):
        buf = ctypes.create_string_buffer(size)
        br = ctypes.c_ulong(0)
        done = 0
        while done < size:
            ptr = ctypes.cast(ctypes.byref(buf, done), ctypes.c_void_p)
            ok = kernel32.ReadFile(
                self.handle, ptr, size - done, ctypes.byref(br), None
            )
            if not ok or br.value == 0:
                return None
            done += br.value
        return buf.raw

    def _write_all(self, data):
        buf = ctypes.create_string_buffer(data)
        bw = ctypes.c_ulong(0)
        done = 0
        total = len(data)
        while done < total:
            ptr = ctypes.cast(ctypes.byref(buf, done), ctypes.c_void_p)
            ok = kernel32.WriteFile(
                self.handle, ptr, total - done, ctypes.byref(bw), None
            )
            if not ok or bw.value == 0:
                return False
            done += bw.value
        return True
