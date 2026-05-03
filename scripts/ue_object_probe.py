import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
from ipc_client import IpcClient


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def read(ipc, address, size):
    data = ipc.read(address, size)
    if data and len(data) >= size:
        return data
    return None


def valid_ptr(value):
    return value is not None and 0x10000 < value < 0x800000000000


class ObjectArray:
    def __init__(self, ipc, address):
        self.ipc = ipc
        self.address = address
        self.num = 0
        self.chunks = []
        self.load()

    def load(self):
        header = read(self.ipc, self.address, 0x20)
        if not header:
            return
        objects = u64(header, 0)
        self.num = u32(header, 0x14)
        chunk_count = u32(header, 0x1C)
        chunk_data = read(self.ipc, objects, chunk_count * 8)
        if not chunk_data:
            return
        for index in range(chunk_count):
            self.chunks.append(u64(chunk_data, index * 8))

    def get(self, index):
        chunk_index = index >> 16
        chunk_offset = index & 0xFFFF
        if chunk_index >= len(self.chunks):
            return None
        chunk = self.chunks[chunk_index]
        item = chunk + chunk_offset * 0x18
        ptr_data = read(self.ipc, item, 8)
        if not ptr_data:
            return None
        ptr = u64(ptr_data, 0)
        if not valid_ptr(ptr):
            return None
        return ptr


def hexdump_qwords(data):
    for offset in range(0, len(data), 8):
        value = u64(data, offset)
        marker = ' ptr' if valid_ptr(value) else ''
        print(f'  +0x{offset:02X}: 0x{value:016X}{marker}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pid', type=int)
    parser.add_argument('indices', nargs='+')
    parser.add_argument('--gobjects', default='0x14E6ADF00')
    args = parser.parse_args()

    ipc = IpcClient(args.pid)
    if not ipc.is_connected():
        print('connect failed')
        return 1

    objects = ObjectArray(ipc, int(args.gobjects, 16))
    print(f'GObjects num={objects.num} chunks={len(objects.chunks)}')

    for text in args.indices:
        index = int(text, 16) if text.lower().startswith('0x') else int(text)
        address = objects.get(index)
        print(f'\nindex=0x{index:X} object=0x{address or 0:X}')
        if not address:
            continue
        data = read(ipc, address, 0x100)
        if data:
            hexdump_qwords(data)

    ipc.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
