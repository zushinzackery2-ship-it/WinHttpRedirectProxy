import struct
import re


def scan_section_for_pattern(data, pattern_bytes, mask=None):
    results = []
    if mask:
        for i in range(len(data) - len(pattern_bytes)):
            match = True
            for j in range(len(pattern_bytes)):
                if mask[j] and data[i + j] != pattern_bytes[j]:
                    match = False
                    break
            if match:
                results.append(i)
    else:
        for i in range(len(data) - len(pattern_bytes)):
            if data[i:i + len(pattern_bytes)] == pattern_bytes:
                results.append(i)
    return results


def resolve_rip_relative(code_data, insn_offset, insn_size):
    disp = struct.unpack_from("<i", code_data, insn_offset + insn_size - 4)[0]
    return insn_offset + insn_size + disp


def find_gnames_by_signature(text_data, text_rva, image_base):
    pattern = bytes([0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00])
    mask =    bytes([0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00])

    candidates = []
    for off in scan_section_for_pattern(text_data, pattern, mask):
        call_byte = text_data[off + 7] if off + 7 < len(text_data) else 0
        if call_byte == 0xE8:
            target = resolve_rip_relative(text_data, off, 7)
            abs_addr = image_base + text_rva + target
            candidates.append({
                "insn_addr": image_base + text_rva + off,
                "lea_target": abs_addr,
                "type": "namepool"
            })

    pattern2 = bytes([0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00])
    mask2 =    bytes([0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00])

    for off in scan_section_for_pattern(text_data, pattern2, mask2):
        if off + 7 < len(text_data) and text_data[off + 7] == 0xE8:
            continue
        target = resolve_rip_relative(text_data, off, 7)
        abs_addr = image_base + text_rva + target
        candidates.append({
            "insn_addr": image_base + text_rva + off,
            "lea_target": abs_addr,
            "type": "namepool_lazy"
        })

    return candidates


def find_gobjects_in_data(data_section, data_rva, image_base):
    candidates = []
    step = 8

    for off in range(0, len(data_section) - 0x20, step):
        chunk = data_section[off:off + 0x20]
        if len(chunk) < 0x20:
            break

        objects_ptr = struct.unpack_from("<Q", chunk, 0)[0]
        max_elements = struct.unpack_from("<I", chunk, 0x10)[0]
        num_elements = struct.unpack_from("<I", chunk, 0x14)[0]
        max_chunks = struct.unpack_from("<I", chunk, 0x18)[0]
        num_chunks = struct.unpack_from("<I", chunk, 0x1C)[0]

        if (1 <= num_chunks <= 0x14
                and 6 <= max_chunks <= 0x5FF
                and num_elements > 0x800
                and max_elements > 0x10000
                and num_elements <= max_elements
                and num_chunks <= max_chunks
                and max_elements % 0x10 == 0):
            epc = max_elements // max_chunks if max_chunks > 0 else 0
            if 0x8000 <= epc <= 0x80000:
                abs_addr = image_base + data_rva + off
                candidates.append({
                    "address": abs_addr,
                    "objects_ptr": objects_ptr,
                    "max_elements": max_elements,
                    "num_elements": num_elements,
                    "max_chunks": max_chunks,
                    "num_chunks": num_chunks,
                    "layout": "chunked_default"
                })

    for off in range(0, len(data_section) - 0x10, step):
        chunk = data_section[off:off + 0x10]
        if len(chunk) < 0x10:
            break

        objects_ptr = struct.unpack_from("<Q", chunk, 0)[0]
        max_elements = struct.unpack_from("<I", chunk, 8)[0]
        num_elements = struct.unpack_from("<I", chunk, 0x0C)[0]

        if (num_elements >= 0x1000
                and max_elements >= 0x1000
                and num_elements <= max_elements
                and max_elements <= 0x400000
                and objects_ptr > 0x10000):
            abs_addr = image_base + data_rva + off
            candidates.append({
                "address": abs_addr,
                "objects_ptr": objects_ptr,
                "max_elements": max_elements,
                "num_elements": num_elements,
                "layout": "fixed"
            })

    return candidates


def scan_data_pointers(data_section, data_rva, image_base, min_addr=0x100000000, max_addr=0x800000000):
    pointers = []
    for off in range(0, len(data_section) - 8, 8):
        val = struct.unpack_from("<Q", data_section, off)[0]
        if min_addr <= val <= max_addr:
            pointers.append({
                "offset": off,
                "abs_addr": image_base + data_rva + off,
                "target": val
            })
    return pointers
