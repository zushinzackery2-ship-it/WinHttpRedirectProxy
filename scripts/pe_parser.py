import struct


class PeSection:
    def __init__(self, name, virtual_addr, virtual_size, raw_size, characteristics):
        self.name = name
        self.virtual_addr = virtual_addr
        self.virtual_size = virtual_size
        self.raw_size = raw_size
        self.characteristics = characteristics

    @property
    def is_readable(self):
        return bool(self.characteristics & 0x40000000)

    @property
    def is_writable(self):
        return bool(self.characteristics & 0x80000000)

    @property
    def is_executable(self):
        return bool(self.characteristics & 0x20000000)

    def contains_rva(self, rva):
        return self.virtual_addr <= rva < self.virtual_addr + self.virtual_size


class PeHeader:
    def __init__(self, image_base, size_of_image, entry_point, sections):
        self.image_base = image_base
        self.size_of_image = size_of_image
        self.entry_point = entry_point
        self.sections = sections

    def find_section_by_name(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def find_section_by_rva(self, rva):
        for s in self.sections:
            if s.contains_rva(rva):
                return s
        return None


def parse_pe_header(data, image_base):
    if len(data) < 0x40:
        return None
    if data[:2] != b"MZ":
        return None

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 >= len(data):
        return None
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None

    opt_hdr_off = e_lfanew + 24
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]

    if len(data) < opt_hdr_off + opt_hdr_size:
        return None

    magic = struct.unpack_from("<H", data, opt_hdr_off)[0]
    if magic == 0x20B:
        size_of_image = struct.unpack_from("<I", data, opt_hdr_off + 56)[0]
        entry_point = struct.unpack_from("<I", data, opt_hdr_off + 16)[0]
        img_base = struct.unpack_from("<Q", data, opt_hdr_off + 24)[0]
    else:
        size_of_image = struct.unpack_from("<I", data, opt_hdr_off + 56)[0]
        entry_point = struct.unpack_from("<I", data, opt_hdr_off + 16)[0]
        img_base = struct.unpack_from("<I", data, opt_hdr_off + 28)[0]

    sections_start = e_lfanew + 24 + opt_hdr_size
    sections = []
    for i in range(num_sections):
        off = sections_start + i * 40
        if off + 40 > len(data):
            break
        sec_data = data[off:off + 40]
        sec_name = sec_data[:8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = struct.unpack_from("<I", sec_data, 8)[0]
        vaddr = struct.unpack_from("<I", sec_data, 12)[0]
        raw_size = struct.unpack_from("<I", sec_data, 16)[0]
        chars = struct.unpack_from("<I", sec_data, 36)[0]
        sections.append(PeSection(sec_name, vaddr, vsize, raw_size, chars))

    return PeHeader(img_base or image_base, size_of_image, entry_point, sections)


def find_module_base(client, hint=0x140000000, module_name=None):
    modules = client.enum_modules()
    if modules:
        if module_name:
            for m in modules:
                if m["name"].lower() == module_name.lower():
                    return m["base"]
        else:
            non_system = [m for m in modules if not m["name"].lower().endswith(".dll")]
            if non_system:
                return non_system[0]["base"]

    candidates = [hint, 0x180000000, 0x1C0000000]
    for base in candidates:
        d = client.read(base, 2)
        if d == b"MZ":
            pe_d = client.read(base + 0x3C, 4)
            if pe_d:
                pe_off = struct.unpack("<I", pe_d)[0]
                if 0 < pe_off < 0x1000:
                    sig = client.read(base + pe_off, 4)
                    if sig == b"PE\x00\x00":
                        return base
    for base in range(0x10000000, 0x200000000, 0x1000000):
        d = client.read(base, 2)
        if d == b"MZ":
            pe_d = client.read(base + 0x3C, 4)
            if pe_d:
                pe_off = struct.unpack("<I", pe_d)[0]
                if 0 < pe_off < 0x1000:
                    sig = client.read(base + pe_off, 4)
                    if sig == b"PE\x00\x00":
                        return base
    return None
