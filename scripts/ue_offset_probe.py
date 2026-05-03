import struct


class FFieldInfo:
    def __init__(self, address, class_name, field_name, next_ptr):
        self.address = address
        self.class_name = class_name
        self.field_name = field_name
        self.next_ptr = next_ptr

    def __repr__(self):
        return f"FField(0x{self.address:X}, '{self.field_name}', cls='{self.class_name}')"


class OffsetResult:
    def __init__(self, ffield_class, ffield_name, ffield_next):
        self.ffield_class = ffield_class
        self.ffield_name = ffield_name
        self.ffield_next = ffield_next

    def is_valid(self):
        return all(x is not None for x in [self.ffield_class, self.ffield_name, self.ffield_next])


class NameResolver:
    def __init__(self, client, gnames_addr, use_pool=True, block_bits=16):
        self.client = client
        self.gnames = gnames_addr
        self.use_pool = use_pool
        self.block_bits = block_bits
        self.shift = None
        self.header_off = 2
        self.string_off = 6
        self.cache = {}
        self.chunks = {}

    def resolve(self, fname_addr, comp_idx_off=0):
        ci = self.client.read_i32(fname_addr + comp_idx_off)
        if ci is None or ci <= 0:
            return None
        if ci in self.cache:
            return self.cache[ci]
        name = self._pool(ci) if self.use_pool else self._array(ci)
        if name:
            self.cache[ci] = name
        return name

    def _pool(self, ci):
        block = ci >> self.block_bits
        in_block = ci & ((1 << self.block_bits) - 1)
        chunk_ptr = self.chunks.get(block)
        if chunk_ptr is None:
            chunk_ptr = self.client.read_ptr(self.gnames + block * 8)
            if not chunk_ptr or chunk_ptr == 0:
                return None
            self.chunks[block] = chunk_ptr
        entry = chunk_ptr + in_block
        hdr = self.client.read_u16(entry + self.header_off)
        if hdr is None:
            return None
        shifts = [self.shift] if self.shift is not None else [0, 6, 1, 2, 3, 4, 5]
        for s in shifts:
            name_len = hdr >> s
            if name_len == 0:
                nxt = self.client.read_i32(entry + self.string_off)
                if nxt and nxt > 0:
                    return self._pool(nxt)
                return None
            if 0 < name_len <= 512:
                self.shift = s
                wide = (hdr & 0x1) != 0
                byte_len = name_len * (2 if wide else 1)
                raw = self.client.read(entry + self.string_off, byte_len)
                if raw:
                    try:
                        if wide:
                            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                        return raw.decode("ascii", errors="replace").rstrip("\x00")
                    except Exception:
                        pass
        return None

    def _array(self, ci):
        dp = self.client.read_ptr(self.gnames)
        cnt = self.client.read_i32(self.gnames + 8)
        if dp is None or cnt is None or ci >= cnt:
            return None
        ep = self.client.read_ptr(dp + ci * 8)
        if not ep:
            return None
        raw = self.client.read(ep + 0x0C, 128)
        if raw:
            n = raw.find(b"\x00")
            if n > 0:
                try:
                    return raw[:n].decode("ascii", errors="replace")
                except Exception:
                    pass
        return None


def probe_ffield_offsets(client, resolver, struct_addr, child_props_off=0x68):
    first = client.read_ptr(struct_addr + child_props_off)
    if not first or first == 0:
        return None

    best_class = None
    best_name = None
    best_next = None

    raw = client.read(first, 0x60)

    for off in range(0x00, 0x40, 8):
        ptr = client.read_ptr(first + off)
        if ptr and ptr != 0:
            ci = client.read_i32(ptr)
            if ci and 0 < ci < 500000:
                name = resolver.resolve(ptr)
                if name and name != "None":
                    if best_class is None:
                        best_class = off
                    break

    for off in range(0x10, 0x40, 4):
        name = resolver.resolve(first + off)
        if name and name != "None" and len(name) > 0:
            if best_name is None:
                best_name = off
            break

    for off in range(0x18, 0x48, 8):
        ptr = client.read_ptr(first + off)
        if ptr and ptr != 0 and ptr != first:
            name = resolver.resolve(ptr + (best_name or 0x28))
            if name and name != "None":
                if best_next is None:
                    best_next = off
                break

    return OffsetResult(best_class, best_name, best_next)


def walk_ffield_chain(client, resolver, struct_addr, child_props_off,
                      next_off, name_off, class_off, max_depth=64):
    first = client.read_ptr(struct_addr + child_props_off)
    if not first or first == 0:
        return []

    visited = set()
    fields = []
    ptr = first

    while ptr and ptr != 0 and len(fields) < max_depth:
        if ptr in visited:
            break
        visited.add(ptr)

        fclass = client.read_ptr(ptr + class_off) if class_off is not None else None
        fname = resolver.resolve(ptr + name_off) if name_off is not None else None
        cls_name = resolver.resolve(fclass) if fclass else None
        next_ptr = client.read_ptr(ptr + next_off) if next_off is not None else None

        fields.append(FFieldInfo(ptr, cls_name, fname, next_ptr))
        ptr = next_ptr

    return fields
