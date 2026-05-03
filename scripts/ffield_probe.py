import struct
from ipc_client import IpcClient


def find_name_array(client, data_base=0x14E28B000, data_size=0xB08E84):
    chunk = 0x100000
    for start in range(0, data_size, chunk):
        read_size = min(chunk + 0x100, data_size - start)
        d = client.read(data_base + start, read_size)
        if not d:
            continue
        for i in range(0, len(d) - 0x20, 0x10):
            idx0 = struct.unpack_from('<Q', d, i)[0]
            ptr0 = struct.unpack_from('<Q', d, i + 8)[0]
            if idx0 != 0 or ptr0 < 0x10000 or ptr0 > 0x800000000000:
                continue
            nd = client.read(ptr0, 0x20)
            if nd:
                name = nd[:16].decode('utf-16-le', errors='replace').split('\x00')[0]
                if name == 'None':
                    table_addr = data_base + start + i
                    return table_addr
    return None


def resolve_name_from_table(client, table_addr, comparison_index):
    entry_addr = table_addr + comparison_index * 16
    d = client.read(entry_addr, 16)
    if not d or len(d) < 16:
        return None
    ptr = struct.unpack_from('<Q', d, 8)[0]
    if ptr < 0x10000:
        return None
    nd = client.read(ptr, 0x80)
    if not nd:
        return None
    name = nd[:128].decode('utf-16-le', errors='replace').split('\x00')[0]
    return name


def read_fnames_at_offset(client, ustruct_addr, child_props_offset, name_offset,
                          count=5, comp_idx_offset=0x0, ffield_stride=0x70):
    child_ptr = client.read_ptr(ustruct_addr + child_props_offset)
    if not child_ptr or child_ptr < 0x10000:
        return []

    names = []
    current = child_ptr
    for _ in range(count):
        if not current or current < 0x10000:
            break
        name_data = client.read(current + name_offset, 8)
        if not name_data:
            break
        comp_idx = struct.unpack_from('<i', name_data, comp_idx_offset)[0]
        if comp_idx < 0 or comp_idx > 0x100000:
            break
        names.append((current, comp_idx))
        next_ptr = client.read_ptr(current + 0x20)
        current = next_ptr

    return names


def find_ffield_offsets(client, table_addr, ustruct_addr, child_off=0x48):
    results = {}
    for name_off in range(0x0, 0x50, 8):
        for comp_off in [0x0, 0x4]:
            fields = read_fnames_at_offset(
                client, ustruct_addr, child_off, name_off,
                count=8, comp_idx_offset=comp_off
            )
            if len(fields) < 2:
                continue

            names = []
            for addr, ci in fields:
                n = resolve_name_from_table(client, table_addr, ci)
                names.append(n)

            unique = set(n for n in names if n)
            if len(unique) >= 2:
                results[(name_off, comp_off)] = names

    return results


def walk_ffield_chain(client, first_field, next_offset, name_offset,
                      comp_idx_offset=0x0, max_fields=20):
    fields = []
    current = first_field
    for _ in range(max_fields):
        if not current or current < 0x10000:
            break
        name_data = client.read(current + name_offset, 8)
        if not name_data:
            break
        comp_idx = struct.unpack_from('<i', name_data, comp_idx_offset)[0]
        if comp_idx < 0 or comp_idx > 0x100000:
            break
        fields.append((current, comp_idx))
        next_ptr = client.read_ptr(current + next_offset)
        current = next_ptr
    return fields
