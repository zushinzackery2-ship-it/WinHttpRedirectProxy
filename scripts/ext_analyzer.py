"""
External FField offset analyzer via WinHttpRedirectProxy IPC.

Reads live game memory through the proxy pipe to:
1. Find ScriptStruct instances with ChildProperties
2. Read FField chain raw bytes
3. Test different Name/Next/Class offset candidates
4. Validate which offsets produce consistent, unique field names
"""
import sys
import struct
from collections import Counter

sys.path.insert(0, r'E:\科研\TEST\WinHttpRedirectProxy-main\scripts')
from ipc_client import IpcClient


class ExtAnalyzer:
    def __init__(self, pid):
        self.c = IpcClient(pid)
        self.gnames = 0x14E7E5010
        self.blocks = []
        self._load_blocks()

    def _load_blocks(self):
        d = self.c.read(self.gnames + 0x10, 164 * 8)
        if d:
            for i in range(164):
                ptr = struct.unpack_from('<Q', d, i * 8)[0]
                self.blocks.append(ptr)

    def read_u8(self, addr):
        d = self.c.read(addr, 1)
        return d[0] if d else None

    def read_u16(self, addr):
        d = self.c.read(addr, 2)
        return struct.unpack('<H', d)[0] if d else None

    def read_u32(self, addr):
        d = self.c.read(addr, 4)
        return struct.unpack('<I', d)[0] if d else None

    def read_i32(self, addr):
        d = self.c.read(addr, 4)
        return struct.unpack('<i', d)[0] if d else None

    def read_ptr(self, addr):
        d = self.c.read(addr, 8)
        return struct.unpack('<Q', d)[0] if d else None

    def read_bytes(self, addr, size):
        return self.c.read(addr, size)

    def is_valid_ptr(self, v):
        return v is not None and 0x10000 < v < 0x800000000000

    def find_scriptstruct_with_children(self, max_scan=200000):
        """Find first ScriptStruct with non-null ChildProperties."""
        ss_class = 0x7ff4ddc84070  # ScriptStruct class address

        chunk0 = 0x3BAA0008
        batch = 0x18 * 500

        for base in range(0, max_scan, 500):
            items = self.read_bytes(chunk0 + base * 0x18, batch)
            if not items:
                continue
            for i in range(500):
                obj_ptr = struct.unpack_from('<Q', items, i * 0x18)[0]
                if not self.is_valid_ptr(obj_ptr):
                    continue
                od = self.read_bytes(obj_ptr, 0x50)
                if not od or len(od) < 0x50:
                    continue
                class_ptr = struct.unpack_from('<Q', od, 0x10)[0]
                if class_ptr != ss_class:
                    continue
                child = struct.unpack_from('<Q', od, 0x48)[0]
                if self.is_valid_ptr(child):
                    name_ci = struct.unpack_from('<I', od, 0x18)[0]
                    return {
                        'addr': obj_ptr,
                        'index': base + i,
                        'name_ci': name_ci,
                        'child': child,
                    }
        return None

    def analyze_ffield_layout(self, ffield_addr, dump_size=0x80):
        """Read raw FField bytes and identify pointer-like fields."""
        d = self.read_bytes(ffield_addr, dump_size)
        if not d:
            return None

        fields = []
        for off in range(0, dump_size, 8):
            v = struct.unpack_from('<Q', d, off)[0]
            is_ptr = self.is_valid_ptr(v)
            fields.append({'offset': off, 'value': v, 'is_ptr': is_ptr})

        return fields

    def find_name_offset_by_variance(self, ffield_addrs, max_offset=0x40):
        """
        For a list of FField addresses, find the offset where
        the uint32 ComparisonIndex values are most diverse.
        The correct Name offset should give unique CIs for different fields.
        """
        print("\n  Scanning FField Name offset candidates:")
        print("  Offset | Values (hex)                              | Unique | Verdict")
        print("  -------+-------------------------------------------+--------+--------")

        best_offset = None
        best_unique = 0

        for off in range(0, max_offset, 4):
            cis = []
            for addr in ffield_addrs:
                ci = self.read_u32(addr + off)
                if ci is not None:
                    cis.append(ci)

            if len(cis) < 2:
                continue

            unique = len(set(cis))
            all_same = unique <= 1
            ci_strs = ["0x%08X" % c for c in cis[:6]]
            ci_display = " ".join(ci_strs)
            if len(cis) > 6:
                ci_display += " ..."

            verdict = ""
            if all_same and len(cis) >= 3:
                verdict = "<<< ALL_SAME"
            elif unique > best_unique:
                best_unique = unique
                best_offset = off
                verdict = "<<< BEST"

            print("  0x%02X   | %-41s |   %2d   | %s" % (off, ci_display, unique, verdict))

        return best_offset

    def walk_ffield_chain(self, first_addr, next_off, name_off, max_depth=10):
        """Walk FField chain and collect (address, comp_idx) pairs."""
        chain = []
        current = first_addr
        for _ in range(max_depth):
            if not self.is_valid_ptr(current):
                break
            ci = self.read_u32(current + name_off)
            chain.append({'addr': current, 'ci': ci})
            nxt = self.read_ptr(current + next_off)
            if not self.is_valid_ptr(nxt):
                break
            current = nxt
        return chain

    def resolve_name_from_blocks(self, comp_idx, stride=2, block_bits=16):
        """Try to resolve a name from the FNamePool blocks."""
        block_size = 1 << block_bits
        block_idx = comp_idx // block_size
        in_block = (comp_idx % block_size) * stride

        if block_idx >= len(self.blocks):
            return None
        bptr = self.blocks[block_idx]
        if not self.is_valid_ptr(bptr):
            return None

        entry_addr = bptr + in_block
        name_data = self.read_bytes(entry_addr, 80)
        if not name_data:
            return None

        # Try decoding as wide string (no header)
        try:
            name = name_data.decode('utf-16-le', errors='replace').split('\x00')[0]
            if name and len(name) > 0 and len(name) < 100:
                return name
        except:
            pass
        return None

    def scan_ffield_offsets(self, scriptstruct):
        """Full analysis of a ScriptStruct's FField chain."""
        child_addr = scriptstruct['child']
        print(f"\n[*] ScriptStruct at 0x{scriptstruct['addr']:X}")
        print(f"    nameCI={scriptstruct['name_ci']}  ChildProperties=0x{child_addr:X}")

        # Step 1: Read first FField raw layout
        print(f"\n[*] First FField at 0x{child_addr:X}:")
        fields = self.analyze_ffield_layout(child_addr)
        if fields:
            for f in fields:
                tag = "PTR" if f['is_ptr'] else "    "
                print(f"    +{f['offset']:02X}: 0x{f['value']:016X}  {tag}")

        # Step 2: Collect multiple FField addresses by following Next candidates
        # Try each pointer offset as potential Next
        print(f"\n[*] Testing Next offset candidates:")
        for next_off in range(0x08, 0x48, 8):
            chain = []
            current = child_addr
            for _ in range(6):
                if not self.is_valid_ptr(current):
                    break
                chain.append(current)
                nxt = self.read_ptr(current + next_off)
                if not self.is_valid_ptr(nxt):
                    break
                # Sanity: next should be different from current
                if nxt == current:
                    break
                current = nxt

            if len(chain) >= 3:
                print(f"    next_off=0x{next_off:02X}: chain length={len(chain)} "
                      f"({' -> '.join('0x%X' % a for a in chain[:4])}...)")

                # Step 3: For each valid Next offset, find the Name offset
                best = self.find_name_offset_by_variance(chain)
                if best is not None:
                    print(f"\n    >>> Best Name offset: 0x{best:02X} (Next=0x{next_off:02X})")

                    # Step 4: Walk the full chain with these offsets
                    full_chain = self.walk_ffield_chain(child_addr, next_off, best, max_depth=20)
                    print(f"\n    Full chain ({len(full_chain)} fields):")
                    for i, entry in enumerate(full_chain[:20]):
                        ci_hex = "0x%X" % entry['ci'] if entry['ci'] is not None else "NULL"
                        print(f"      [{i:2d}] 0x{entry['addr']:X}  CI={ci_hex}")

    def run(self):
        print("=" * 70)
        print("External FField Offset Analyzer")
        print("=" * 70)

        # Step 0: Verify connection
        mods = self.c.enum_modules()
        if not mods:
            print("[!] Cannot enumerate modules")
            return
        print(f"[+] Connected, {len(mods)} modules loaded")

        # Step 1: Find a live ScriptStruct with ChildProperties
        print("\n[*] Searching for ScriptStruct with ChildProperties...")
        ss = self.find_scriptstruct_with_children()
        if not ss:
            print("[!] No ScriptStruct with ChildProperties found")
            return

        # Step 2: Analyze FField layout
        self.scan_ffield_offsets(ss)

        self.c.close()


if __name__ == '__main__':
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 15200
    analyzer = ExtAnalyzer(pid)
    analyzer.run()
