"""
IPC-based UE5 SDK Dumper
Reads game memory via WinHttpRedirectProxy pipe to dump SDK structures.
"""
import struct
import sys
import os
from dataclasses import dataclass, field
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))
from ipc_client import IpcClient


# ─── Memory Reader ───────────────────────────────────────────────────

class MemReader:
    def __init__(self, ipc: IpcClient):
        self.ipc = ipc
        self.cache = {}

    def u8(self, addr):
        d = self.ipc.read(addr, 1)
        return d[0] if d else None

    def u16(self, addr):
        d = self.ipc.read(addr, 2)
        return struct.unpack('<H', d)[0] if d else None

    def u32(self, addr):
        d = self.ipc.read(addr, 4)
        return struct.unpack('<I', d)[0] if d else None

    def i32(self, addr):
        d = self.ipc.read(addr, 4)
        return struct.unpack('<i', d)[0] if d else None

    def u64(self, addr):
        d = self.ipc.read(addr, 8)
        return struct.unpack('<Q', d)[0] if d else None

    def ptr(self, addr):
        return self.u64(addr)

    def bytes(self, addr, size):
        return self.ipc.read(addr, size)

    def str_utf16(self, addr, max_len=256):
        d = self.ipc.read(addr, max_len)
        if not d:
            return None
        try:
            return d.decode('utf-16-le', errors='replace').split('\x00')[0]
        except:
            return None

    def valid_ptr(self, v):
        # Strict: must be above 4GB to be a heap pointer
        return v is not None and 0x100000000 < v < 0x800000000000


# ─── GObjects ────────────────────────────────────────────────────────

@dataclass
class UObject:
    index: int
    address: int
    vtable: int = 0
    flags: int = 0
    class_private: int = 0
    name_index: int = 0
    outer: int = 0


class ObjectArray:
    def __init__(self, mem: MemReader, gobjects_addr: int):
        self.mem = mem
        self.gobjects_addr = gobjects_addr
        self.num_elements = 0
        self.max_elements = 0
        self.num_chunks = 0
        self.chunk_ptrs = []
        self._init()

    def _init(self):
        m = self.mem
        d = m.bytes(self.gobjects_addr, 0x20)
        if not d:
            return
        self.num_elements = m.u32(self.gobjects_addr + 0x14) or 0
        self.max_elements = m.u32(self.gobjects_addr + 0x10) or 0
        self.num_chunks = m.u32(self.gobjects_addr + 0x1C) or 0
        objects_ptr = m.u64(self.gobjects_addr) or 0
        if objects_ptr > 0x10000 and self.num_chunks > 0:
            cd = m.bytes(objects_ptr, self.num_chunks * 8)
            if cd:
                for i in range(self.num_chunks):
                    self.chunk_ptrs.append(struct.unpack_from('<Q', cd, i * 8)[0])

    def get(self, index: int) -> Optional[UObject]:
        if index < 0 or index >= self.num_elements:
            return None
        chunk_idx = index >> 16  # assuming 0x10000 per chunk
        in_chunk = index & 0xFFFF
        if chunk_idx >= len(self.chunk_ptrs):
            return None
        cp = self.chunk_ptrs[chunk_idx]
        if cp < 0x10000:
            return None
        item_addr = cp + in_chunk * 0x18
        obj_ptr = self.mem.ptr(item_addr)
        if not self.mem.valid_ptr(obj_ptr):
            return None
        d = self.mem.bytes(obj_ptr, 0x28)
        if not d or len(d) < 0x28:
            return None
        obj = UObject(index=index, address=obj_ptr)
        obj.vtable = struct.unpack_from('<Q', d, 0)[0]
        obj.class_private = struct.unpack_from('<Q', d, 0x10)[0]
        obj.name_index = struct.unpack_from('<I', d, 0x18)[0]
        obj.outer = struct.unpack_from('<Q', d, 0x20)[0]
        return obj

    def iter(self, max_count=None):
        count = max_count or self.num_elements
        for i in range(min(count, self.num_elements)):
            obj = self.get(i)
            if obj:
                yield obj


# ─── FNamePool ───────────────────────────────────────────────────────

class NamePool:
    def __init__(self, mem: MemReader, gnames_addr: int, dump_file: str = None):
        self.mem = mem
        self.gnames_addr = gnames_addr
        self.blocks = []
        self.block_bits = 16
        self.stride = 2
        self._ci_to_name = {}  # ComparisonIndex -> name mapping from dump
        self._init()
        if dump_file:
            self._load_dump_names(dump_file)

    def _init(self):
        m = self.mem
        best_blocks = []
        best_offset = 0
        best_count = 0

        for start_off in range(0, 0x40, 8):
            d = m.bytes(self.gnames_addr + start_off, 300 * 8)
            if not d:
                continue
            blocks = []
            non_null = 0
            for i in range(300):
                ptr = struct.unpack_from('<Q', d, i * 8)[0]
                if 0x140000000 < ptr < 0x150000000:
                    blocks.append(ptr)
                    non_null += 1
                else:
                    blocks.append(0)
            if non_null > best_count:
                best_count = non_null
                best_blocks = blocks
                best_offset = start_off

        if best_count >= 10:
            self.blocks = best_blocks

    def _load_dump_names(self, dump_file: str):
        """Load name mapping from GObjects-Dump-WithProperties.txt.
        Maps UObject index -> short name (last component of full name)."""
        try:
            with open(dump_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith('['):
                        continue
                    try:
                        # [0000291C] {0x7ff4de1874e0} ScriptStruct CoreUObject.Guid
                        bracket_end = line.index(']')
                        idx_str = line[1:bracket_end]
                        idx = int(idx_str, 16)

                        brace_end = line.index('}')
                        rest = line[brace_end+1:].strip()
                        tokens = rest.split()
                        if len(tokens) >= 2:
                            # Last token is the short name
                            name = tokens[-1]
                            self._ci_to_name[idx] = name
                    except:
                        continue
        except Exception as e:
            print(f"[!] Failed to load dump names: {e}")

    def resolve(self, comparison_index: int) -> Optional[str]:
        """Resolve a ComparisonIndex to a name string."""
        if comparison_index <= 0:
            return None

        # First try dump mapping
        if comparison_index in self._ci_to_name:
            return self._ci_to_name[comparison_index]

        # Try FNamePool resolution
        if not self.blocks:
            return None

        block_size = 1 << self.block_bits
        block_idx = comparison_index // block_size
        in_block = (comparison_index % block_size) * self.stride

        if block_idx >= len(self.blocks):
            return None
        bptr = self.blocks[block_idx]
        if not self.mem.valid_ptr(bptr):
            return None

        entry_addr = bptr + in_block
        name_data = self.mem.bytes(entry_addr, 80)
        if not name_data:
            return None
        try:
            name = name_data.decode('utf-16-le', errors='replace').split('\x00')[0]
            if name and 0 < len(name) < 100:
                return name
        except:
            pass
        return None


# ─── FField / FProperty ─────────────────────────────────────────────

@dataclass
class FFieldInfo:
    address: int
    vtable: int = 0
    class_ptr: int = 0
    class_name: str = ""
    owner: int = 0
    next_ptr: int = 0
    name_index: int = 0
    name: str = ""
    offset: int = 0
    size: int = 0
    array_dim: int = 1


# ─── UStruct Scanner ────────────────────────────────────────────────

class StructScanner:
    def __init__(self, mem: MemReader, names: NamePool):
        self.mem = mem
        self.names = names
        # Offsets (will be auto-detected)
        self.off_class = 0x08
        self.off_name = 0x0C
        self.off_next = 0x18
        self.off_child = 0x48
        self.off_super = 0x40
        self.off_size = 0x58

    def read_ffield_chain(self, first_addr: int, max_depth=200):
        """Walk FField chain and collect field info."""
        fields = []
        current = first_addr
        visited = set()
        for _ in range(max_depth):
            if not self.mem.valid_ptr(current) or current in visited:
                break
            visited.add(current)

            d = self.mem.bytes(current, 0x40)
            if not d or len(d) < 0x40:
                break

            f = FFieldInfo(address=current)
            f.vtable = struct.unpack_from('<Q', d, 0)[0]
            f.class_ptr = struct.unpack_from('<Q', d, self.off_class)[0] if self.off_class < 0x38 else 0
            f.name_index = struct.unpack_from('<I', d, self.off_name)[0] if self.off_name < 0x3C else 0
            f.next_ptr = struct.unpack_from('<Q', d, self.off_next)[0] if self.off_next < 0x38 else 0

            f.name = self.names.resolve(f.name_index) or f"unk_{f.name_index:X}"
            fields.append(f)

            if not self.mem.valid_ptr(f.next_ptr):
                break
            current = f.next_ptr

        return fields

    def detect_offsets(self, test_addrs: list):
        """Auto-detect FField offsets by analyzing multiple FField objects."""
        if len(test_addrs) < 4:
            return False

        # Read raw bytes from all FFields
        raw_data = []
        for addr in test_addrs[:20]:
            d = self.mem.bytes(addr, 0x40)
            if d and len(d) >= 0x40:
                raw_data.append((addr, d))

        if len(raw_data) < 4:
            return False

        # Find Name offset: look for offset with high variance and small values
        best_name_off = None
        best_score = 0
        for off in range(8, 0x3C, 4):
            values = []
            for addr, d in raw_data:
                v = struct.unpack_from('<I', d, off)[0]
                values.append(v)
            unique = len(set(values))
            # Score: high unique + values look like ComparisonIndex (< 0x400000)
            pointer_like = sum(1 for v in values if v > 0x100000)
            score = unique - pointer_like * 2
            if score > best_score and unique >= len(values) * 0.5:
                best_score = score
                best_name_off = off

        if best_name_off is not None:
            self.off_name = best_name_off
            # Class is typically right before Name (uint32)
            self.off_class = best_name_off - 4
            if self.off_class < 0:
                self.off_class = 0x08

        # Find Next offset: look for offset with valid heap pointers
        # that are DIFFERENT from Owner (at +0x10)
        owner_off = 0x10  # Owner is typically at +0x10
        for off in range(0x18, 0x40, 8):
            values = []
            for addr, d in raw_data:
                v = struct.unpack_from('<Q', d, off)[0]
                values.append(v)
            # Next pointers should be valid addresses, different from each other
            valid_count = sum(1 for v in values if self.mem.valid_ptr(v))
            unique = len(set(values))
            # Check that values are NOT the same as Owner
            owner_vals = set()
            for addr, d in raw_data:
                ov = struct.unpack_from('<Q', d, owner_off)[0]
                owner_vals.add(ov)
            overlap = len(set(values) & owner_vals)
            if valid_count >= len(values) * 0.8 and unique >= 3 and overlap == 0:
                self.off_next = off
                break

        return True

    def get_struct_info(self, obj: UObject) -> dict:
        """Read UStruct-specific fields."""
        m = self.mem
        d = m.bytes(obj.address, 0x80)
        if not d or len(d) < 0x60:
            return {}

        child = m.ptr(obj.address + self.off_child) if self.off_child < 0x58 else 0
        super_struct = m.ptr(obj.address + self.off_super) if self.off_super < 0x58 else 0
        struct_size = m.u32(obj.address + self.off_size) if self.off_size < 0x5C else 0

        return {
            'child_properties': child,
            'super_struct': super_struct,
            'struct_size': struct_size,
        }


# ─── Main Dumper ─────────────────────────────────────────────────────

class IpcDumper:
    def __init__(self, pid: int):
        self.pid = pid
        self.ipc = IpcClient(pid)
        self.mem = MemReader(self.ipc)
        self.objects = None
        self.names = None
        self.scanner = None

    def init_gobjects(self, addr: int):
        self.objects = ObjectArray(self.mem, addr)
        print(f"[+] GObjects: {self.objects.num_elements} objects, {self.objects.num_chunks} chunks")

    def init_names(self, addr: int, dump_file: str = None):
        self.names = NamePool(self.mem, addr, dump_file)
        print(f"[+] FNamePool: {len(self.names.blocks)} blocks")
        non_null = [(i, b) for i, b in enumerate(self.names.blocks) if b > 0]
        if non_null:
            print(f"    Non-null blocks: {len(non_null)}")
        if self.names._ci_to_name:
            print(f"    Dump names loaded: {len(self.names._ci_to_name)} entries")
        # Test resolution
        test = self.names.resolve(0)
        print(f"    CI=0 -> '{test}'")

    def init_scanner(self):
        self.scanner = StructScanner(self.mem, self.names)

    def find_ffield_test_set(self, max_scan=100000):
        """Find multiple objects with ChildProperties for offset detection."""
        test_addrs = []
        chunk0 = self.objects.chunk_ptrs[0] if self.objects.chunk_ptrs else 0
        if chunk0 < 0x10000:
            return test_addrs

        batch = 0x18 * 500
        for base in range(0, max_scan, 500):
            if len(test_addrs) >= 20:
                break
            items = self.mem.bytes(chunk0 + base * 0x18, batch)
            if not items:
                continue
            for i in range(500):
                obj_ptr = struct.unpack_from('<Q', items, i * 0x18)[0]
                if not self.mem.valid_ptr(obj_ptr):
                    continue
                od = self.mem.bytes(obj_ptr, 0x50)
                if not od or len(od) < 0x50:
                    continue
                child = struct.unpack_from('<Q', od, 0x48)[0]
                if self.mem.valid_ptr(child):
                    test_addrs.append(child)

        return test_addrs

    def dump_struct(self, obj: UObject, max_fields=50) -> dict:
        """Dump a UStruct with its FField chain."""
        info = self.scanner.get_struct_info(obj)
        if not info.get('child_properties'):
            return {}

        fields = self.scanner.read_ffield_chain(info['child_properties'], max_depth=max_fields)
        return {
            'object': obj,
            'info': info,
            'fields': fields,
        }

    def dump_sdk_sample(self, count=10, output_file=None):
        """Dump a sample of structs to verify field names."""
        lines = []
        dumped = 0

        for obj in self.objects.iter(max_count=200000):
            if dumped >= count:
                break

            # Check if this is a UStruct (has ChildProperties)
            od = self.mem.bytes(obj.address, 0x50)
            if not od or len(od) < 0x50:
                continue
            child = struct.unpack_from('<Q', od, 0x48)[0]
            if not self.mem.valid_ptr(child):
                continue

            name = self.names.resolve(obj.index) or self.names.resolve(obj.name_index) or f"unk_{obj.name_index:X}"
            result = self.dump_struct(obj, max_fields=30)
            if not result or not result.get('fields'):
                continue

            lines.append(f"\n{'='*60}")
            lines.append(f"Struct: {name} (0x{obj.address:X}, CI={obj.name_index})")
            lines.append(f"  ChildProperties: 0x{child:X}")
            si = result['info']
            if si.get('super_struct'):
                lines.append(f"  SuperStruct: 0x{si['super_struct']:X}")
            if si.get('struct_size'):
                lines.append(f"  Size: 0x{si['struct_size']:X}")
            lines.append(f"  Fields ({len(result['fields'])}):")

            for i, f in enumerate(result['fields']):
                lines.append(f"    [{i:2d}] 0x{f.address:X}  name='{f.name}' (CI={f.name_index})  class=0x{f.class_ptr:X}")

            # Check for TinyFont duplication
            field_names = [f.name for f in result['fields']]
            if field_names.count('TinyFont') > 1:
                lines.append(f"  [!!!] TinyFont DUPLICATION DETECTED ({field_names.count('TinyFont')} times)")

            dumped += 1

        output = '\n'.join(lines)
        print(output)

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"\n[+] Saved to {output_file}")

        return lines

    def close(self):
        self.ipc.close()


# ─── CLI ─────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="IPC-based UE5 SDK Dumper")
    parser.add_argument("pid", type=int, help="Target process PID")
    parser.add_argument("--gobjects", default="0x14E6ADF00", help="GObjects address (hex)")
    parser.add_argument("--gnames", default="0x14E7E5010", help="GNames address (hex)")
    parser.add_argument("--count", type=int, default=10, help="Number of structs to dump")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--dump", help="Path to GObjects-Dump-WithProperties.txt for name mapping")
    args = parser.parse_args()

    dumper = IpcDumper(args.pid)

    print("[*] Initializing GObjects...")
    dumper.init_gobjects(int(args.gobjects, 16))

    print("[*] Initializing FNamePool...")
    dumper.init_names(int(args.gnames, 16), args.dump)

    print("[*] Initializing scanner...")
    dumper.init_scanner()

    print("[*] Finding FField test set for offset detection...")
    test_addrs = dumper.find_ffield_test_set()
    print(f"    Found {len(test_addrs)} FField addresses")

    if len(test_addrs) >= 4:
        print("[*] Auto-detecting FField offsets...")
        dumper.scanner.detect_offsets(test_addrs)
        print(f"    Class=0x{dumper.scanner.off_class:X}  Name=0x{dumper.scanner.off_name:X}  Next=0x{dumper.scanner.off_next:X}")

    print(f"\n[*] Dumping {args.count} structs...")
    dumper.dump_sdk_sample(count=args.count, output_file=args.output)

    dumper.close()


if __name__ == '__main__':
    main()
