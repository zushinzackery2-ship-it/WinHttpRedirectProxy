import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
from ipc_client import IpcClient


def is_ptr(value):
    return value is not None and 0x10000 < value < 0x800000000000


def read(client, address, size):
    data = client.read(address, size)
    if data and len(data) >= size:
        return data
    return None


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def print_qwords(label, address, data, limit):
    print(f'\n{label} 0x{address:X}')
    for offset in range(0, min(len(data), limit), 8):
        value = u64(data, offset)
        marker = ' ptr' if is_ptr(value) else ''
        print(f'  +0x{offset:02X}: 0x{value:016X}{marker}')


def looks_like_ffield(client, address):
    data = read(client, address, 0x80)
    if not data:
        return False
    first = u64(data, 0)
    second = u64(data, 8)
    owner = u64(data, 0x10)
    return is_ptr(first) and (is_ptr(second) or is_ptr(owner))


def walk_candidate(client, first, next_offsets, depth):
    for next_offset in next_offsets:
        current = first
        seen = set()
        rows = []
        for _ in range(depth):
            if not is_ptr(current) or current in seen:
                break
            seen.add(current)
            data = read(client, current, 0x80)
            if not data:
                break
            values32 = [u32(data, offset) for offset in range(0, 0x40, 4)]
            next_value = u64(data, next_offset)
            rows.append((current, next_value, values32))
            current = next_value
        if rows:
            print(f'\nchain first=0x{first:X} next_off=0x{next_offset:X} depth={len(rows)}')
            for index, (address, next_value, values32) in enumerate(rows[:12]):
                sample = ' '.join(f'{value:08X}' for value in values32[:10])
                print(f'  [{index:02d}] addr=0x{address:X} next=0x{next_value:X} u32={sample}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pid', type=int)
    parser.add_argument('struct_addr', help='hex address')
    parser.add_argument('--size', default='0x100')
    args = parser.parse_args()

    client = IpcClient(args.pid)
    if not client.is_connected():
        print('connect failed')
        return 1

    struct_addr = int(args.struct_addr, 16)
    size = int(args.size, 16)
    data = read(client, struct_addr, size)
    if not data:
        print('struct read failed')
        return 1

    print_qwords('struct', struct_addr, data, size)

    candidates = []
    for offset in range(0, min(size, 0x100), 8):
        value = u64(data, offset)
        if not is_ptr(value):
            continue
        target = read(client, value, 0x40)
        if not target:
            continue
        if looks_like_ffield(client, value):
            candidates.append((offset, value))
            print_qwords(f'candidate +0x{offset:X}', value, target, 0x40)

    next_offsets = list(range(0x18, 0x80, 8))
    for offset, value in candidates:
        print(f'\nwalking candidate struct+0x{offset:X}=0x{value:X}')
        walk_candidate(client, value, next_offsets, 16)

    client.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
