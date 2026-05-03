"""
External FField offset analyzer v2.

Strategy: find multiple ScriptStructs, read their first FField,
compare raw bytes at each offset to find which one contains
the FName ComparisonIndex (should differ between different structs).
"""
import sys
import struct
from collections import Counter

sys.path.insert(0, r'E:\科研\TEST\WinHttpRedirectProxy-main\scripts')
from ipc_client import IpcClient


class ExtAnalyzerV2:
    def __init__(self, pid):
        self.c = IpcClient(pid)

    def read_u32(self, addr):
        d = self.c.read(addr, 4)
        return struct.unpack('<I', d)[0] if d else None

    def read_ptr(self, addr):
        d = self.c.read(addr, 8)
        return struct.unpack('<Q', d)[0] if d else None

    def is_valid_ptr(self, v):
        return v is not None and 0x10000 < v < 0x800000000000

    def find_scriptstructs(self, count=20, max_scan=200000):
        """Find objects with readable ChildProperties."""
        chunk0 = 0x3BAA0008
        results = []
        batch = 0x18 * 1000

        for base in range(0, max_scan, 1000):
            if len(results) >= count:
                break
            items = self.c.read(chunk0 + base * 0x18, batch)
            if not items:
                continue
            for i in range(1000):
                if len(results) >= count:
                    break
                obj_ptr = struct.unpack_from('<Q', items, i * 0x18)[0]
                if not self.is_valid_ptr(obj_ptr):
                    continue
                od = self.c.read(obj_ptr, 0x50)
                if not od or len(od) < 0x50:
                    continue
                child = struct.unpack_from('<Q', od, 0x48)[0]
                if self.is_valid_ptr(child):
                    fd = self.c.read(child, 8)
                    if fd:
                        name_ci = struct.unpack_from('<I', od, 0x18)[0]
                        class_ptr = struct.unpack_from('<Q', od, 0x10)[0]
                        results.append({
                            'addr': obj_ptr,
                            'name_ci': name_ci,
                            'child': child,
                            'class': class_ptr,
                        })
        return results

    def analyze_offsets_statistically(self, ffield_addrs, max_offset=0x40):
        """
        For each offset, read uint32 from all FField addresses.
        The correct FName offset should show HIGH variance (different CIs).
        Wrong offsets should show LOW variance (same values).
        """
        print("\n  Offset | Unique | Sample values                          | Verdict")
        print("  -------+--------+----------------------------------------+--------")

        best_offset = None
        best_score = 0

        for off in range(0, max_offset, 4):
            values = []
            for addr in ffield_addrs:
                v = self.read_u32(addr + off)
                if v is not None:
                    values.append(v)

            if len(values) < 3:
                continue

            counter = Counter(values)
            unique = len(counter)
            most_common_count = counter.most_common(1)[0][1]

            # Score: high unique count = likely FName offset
            # Penalty: if most common value appears > 50% = likely not FName
            score = unique
            if most_common_count > len(values) * 0.5:
                score = 0

            sample = " ".join("0x%08X" % v for v in values[:5])
            if len(values) > 5:
                sample += " ..."

            verdict = ""
            if score > best_score:
                best_score = score
                best_offset = off
                verdict = "<<< BEST"
            elif unique <= 1:
                verdict = "<<< ALL_SAME"
            elif most_common_count > len(values) * 0.5:
                verdict = "<<< DOMINANT"

            print("  0x%02X   |   %2d   | %-38s | %s" % (off, unique, sample, verdict))

        return best_offset, best_score

    def run(self):
        print("=" * 70)
        print("External FField Offset Analyzer v2 (Statistical)")
        print("=" * 70)

        # Step 1: Find ScriptStructs
        print("\n[*] Finding ScriptStructs with ChildProperties...")
        structs = self.find_scriptstructs(count=30)
        print(f"    Found {len(structs)} ScriptStructs")

        if len(structs) < 3:
            print("[!] Need at least 3 ScriptStructs")
            return

        # Step 2: Read first FField from each
        print("\n[*] Reading first FField from each struct...")
        ffield_addrs = []
        for ss in structs:
            child = ss['child']
            # Verify the FField is readable
            d = self.c.read(child, 4)
            if d:
                ffield_addrs.append(child)
                print(f"    0x{child:X} (from struct nameCI={ss['name_ci']})")

        print(f"\n    {len(ffield_addrs)} readable FFields")

        # Step 3: Statistical offset analysis
        print("\n[*] Statistical offset analysis (all FFields):")
        best_off, best_score = self.analyze_offsets_statistically(ffield_addrs)

        if best_off is not None:
            print(f"\n  >>> Best FName offset candidate: 0x{best_off:02X} (score={best_score})")
        else:
            print("\n  >>> No clear FName offset found")

        # Step 4: Also test with just the first few FFields (to match dumper behavior)
        if len(ffield_addrs) >= 4:
            print(f"\n[*] Testing with first 4 FFields (simulates Guid/Vector validation):")
            subset = ffield_addrs[:4]
            best_off_sub, _ = self.analyze_offsets_statistically(subset)
            if best_off_sub is not None:
                print(f"\n  >>> Best offset with 4 fields: 0x{best_off_sub:02X}")

                # Step 5: Check if the offset found with 4 fields matches the full set
                if best_off_sub != best_off:
                    print(f"\n  [!] MISMATCH! 4-field offset (0x{best_off_sub:02X}) != "
                          f"full offset (0x{best_off:02X})")
                    print(f"      This explains the TinyFont bug: the dumper validates with")
                    print(f"      only Guid/Vector (4 fields) and picks the wrong offset.")
                else:
                    print(f"\n  [OK] 4-field offset matches full offset.")

        # Step 6: For each FField, read raw bytes and show the full layout
        print(f"\n[*] Sample FField raw layout (first 3):")
        for i, addr in enumerate(ffield_addrs[:3]):
            d = self.c.read(addr, 0x40)
            if d:
                print(f"\n  FField[{i}] at 0x{addr:X}:")
                for off in range(0, 0x40, 4):
                    v = struct.unpack_from('<I', d, off)[0]
                    print(f"    +{off:02X}: 0x{v:08X}")

        self.c.close()


if __name__ == '__main__':
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 15200
    analyzer = ExtAnalyzerV2(pid)
    analyzer.run()
