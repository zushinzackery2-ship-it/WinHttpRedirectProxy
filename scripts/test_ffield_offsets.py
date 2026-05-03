import sys
sys.path.insert(0, r'E:\科研\TEST\WinHttpRedirectProxy-main\scripts')
from ipc_client import IpcClient
import struct

c = IpcClient(15200)

def read_u32(addr):
    d = c.read(addr, 4)
    if d and len(d) >= 4:
        return struct.unpack_from('<I', d, 0)[0]
    return None

# Guid FField addresses from GObjects-Dump-WithProperties.txt
# A=0xa0f55c60, B=0xa0f55bf0, C=0xa0f55b80, D=0xa0f55950
guid_fields = [0xa0f55c60, 0xa0f55bf0, 0xa0f55b80, 0xa0f55950]
guid_names = ["A", "B", "C", "D"]

print("=== Guid.A FField raw bytes ===")
d = c.read(guid_fields[0], 0x40)
if d:
    for i in range(0, 0x40, 4):
        v = struct.unpack_from('<I', d, i)[0]
        print("  +%02X: 0x%08X" % (i, v))

print("\n=== Testing FField::Name offsets ===")
print("Read ComparisonIndex at each offset from all 4 Guid fields:\n")

for name_off in range(0, 0x40, 4):
    cis = []
    for addr in guid_fields:
        ci = read_u32(addr + name_off)
        cis.append(ci)

    valid = [c for c in cis if c is not None and c > 0]
    unique = len(set(valid))
    all_same = len(valid) >= 3 and unique <= 1
    none_count = sum(1 for c in cis if c is None)

    ci_strs = []
    for i, ci in enumerate(cis):
        if ci is not None:
            ci_strs.append("%s=0x%X" % (guid_names[i], ci))
        else:
            ci_strs.append("%s=NULL" % guid_names[i])

    marker = " <<< REJECT" if all_same else ""
    print("off=0x%02X: %s  unique=%d%s" % (
        name_off, "  ".join(ci_strs), unique, marker))

c.close()
