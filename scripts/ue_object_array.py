import struct


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def valid_ptr(value):
    return value is not None and 0x10000 < value < 0x800000000000


def read_exact(ipc, address, size):
    data = ipc.read(address, size)
    if data and len(data) >= size:
        return data
    return None


class ObjectArray:
    def __init__(self, ipc, address):
        self.ipc = ipc
        self.address = address
        self.num = 0
        self.max = 0
        self.chunk_count = 0
        self.chunks = []
        self.load()

    def load(self):
        header = read_exact(self.ipc, self.address, 0x20)
        if not header:
            return
        objects = u64(header, 0)
        self.max = u32(header, 0x10)
        self.num = u32(header, 0x14)
        self.chunk_count = u32(header, 0x1C)
        chunk_data = read_exact(self.ipc, objects, self.chunk_count * 8)
        if not chunk_data:
            return
        for index in range(self.chunk_count):
            self.chunks.append(u64(chunk_data, index * 8))

    def get_address(self, index):
        if index < 0 or index >= self.num:
            return None
        chunk_index = index >> 16
        chunk_offset = index & 0xFFFF
        if chunk_index >= len(self.chunks):
            return None
        chunk = self.chunks[chunk_index]
        item = chunk + chunk_offset * 0x18
        ptr_data = read_exact(self.ipc, item, 8)
        if not ptr_data:
            return None
        address = u64(ptr_data, 0)
        return address if valid_ptr(address) else None
