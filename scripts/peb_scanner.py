import struct

PEB_IMAGE_BASE_OFF = 0x10
PEB_LDR_OFF = 0x18
LDR_LEN_OFF = 0x00
LDR_INIT_OFF = 0x04
LDR_IN_MEM_ORDER_OFF = 0x20
ENTRY_DLL_BASE_OFF = 0x30
ENTRY_SIZE_IMAGE_OFF = 0x40
ENTRY_BASE_NAME_OFF = 0x58
UNICODE_BUF_OFF = 0x08


class ModuleInfo:
    def __init__(self, base, size, name):
        self.base = base
        self.size = size
        self.name = name

    def __repr__(self):
        return f"Module({self.name}, base=0x{self.base:X}, size=0x{self.size:X})"


def find_peb(client, known_module_base, scan_end=0x100000000, block_size=16384):
    needle = struct.pack("<Q", known_module_base)
    mutant_pattern = b"\xff\xff\xff\xff\xff\xff\xff\xff"

    for addr in range(0x10000, scan_end, block_size):
        block = client.read(addr, block_size)
        if not block:
            continue

        pos = 0
        while True:
            idx = block.find(needle, pos)
            if idx < 0:
                break

            if idx >= 0x10:
                page_off = idx - 0x10
                if page_off % 0x1000 == 0:
                    mutant_off = page_off + 0x08
                    if mutant_off + 8 <= len(block):
                        mutant_val = block[mutant_off:mutant_off + 8]
                        if mutant_val == mutant_pattern:
                            peb_addr = addr + page_off
                            if _verify_peb(client, peb_addr):
                                return peb_addr

            pos = idx + 1

    return None


def _verify_peb(client, peb_addr):
    ldr_ptr = client.read_ptr(peb_addr + PEB_LDR_OFF)
    if not ldr_ptr or ldr_ptr < 0x10000:
        return False

    length = client.read_u32(ldr_ptr + LDR_LEN_OFF)
    if length is None or length > 0x100:
        return False

    init_val = client.read_u32(ldr_ptr + LDR_INIT_OFF)
    if init_val is None:
        return False

    return (init_val & 0xFF) == 1


def enumerate_modules(client, peb_addr):
    ldr_ptr = client.read_ptr(peb_addr + PEB_LDR_OFF)
    if not ldr_ptr:
        return []

    list_head = ldr_ptr + LDR_IN_MEM_ORDER_OFF
    first_flink = client.read_ptr(list_head)
    if not first_flink:
        return []

    modules = []
    flink = first_flink
    seen = set()
    max_iter = 256

    for _ in range(max_iter):
        if flink in seen or flink == 0:
            break
        seen.add(flink)

        entry_addr = flink - ENTRY_DLL_BASE_OFF + ENTRY_DLL_BASE_OFF
        entry_addr = flink - 0x20

        dll_base = client.read_ptr(entry_addr + ENTRY_DLL_BASE_OFF)
        size_img = client.read_u32(entry_addr + ENTRY_SIZE_IMAGE_OFF)
        name = _read_unicode_string(client, entry_addr + ENTRY_BASE_NAME_OFF)

        if dll_base and dll_base > 0x10000:
            modules.append(ModuleInfo(dll_base, size_img or 0, name or ""))

        next_flink = client.read_ptr(flink)
        if next_flink == list_head or next_flink == 0:
            break
        flink = next_flink

    return modules


def _read_unicode_string(client, addr):
    length = client.read_u16(addr)
    buf_ptr = client.read_ptr(addr + UNICODE_BUF_OFF)
    if not length or not buf_ptr or length > 1024:
        return None
    raw = client.read(buf_ptr, length)
    if not raw:
        return None
    try:
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return None


def find_main_module(modules, name_hint=""):
    name_lower = name_hint.lower()
    for m in modules:
        if m.name.lower().endswith(".exe"):
            if name_lower and name_lower not in m.name.lower():
                continue
            return m
    if modules:
        return modules[0]
    return None
