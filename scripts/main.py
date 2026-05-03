import argparse
import sys

from ipc_client import IpcClient
from pe_parser import parse_pe_header, find_module_base
from ue_offset_probe import NameResolver, probe_ffield_offsets, walk_ffield_chain
from globals_scan import find_gnames_by_signature, find_gobjects_in_data, scan_data_pointers


def hexdump(data, base_addr=0):
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {base_addr + i:010X}: {hx:<48s} {asc}")


def cmd_read(client, args):
    addr = int(args.addr, 16)
    size = int(args.size, 16)
    data = client.read(addr, size)
    if data:
        hexdump(data, addr)
        print(f"\nread {len(data)} bytes OK")
    else:
        print("[!] read failed")
        return 1
    return 0


def cmd_modules(client, args):
    modules = client.enum_modules()
    if modules is None:
        print("[!] enum_modules failed")
        return 1
    print(f"[+] {len(modules)} modules loaded:\n")
    for m in modules:
        print(f"  0x{m['base']:016X}  size=0x{m['size']:08X}  {m['name']}")
    return 0


def cmd_load(client, args):
    reply = client.load_dll(args.dll)
    if not reply:
        print("[!] load request failed")
        return 1
    print(f"status={reply['status']} win32={reply['win32_error']} module=0x{reply['module']:X}")
    print(f"text={reply['text']}")
    print(f"path={reply['path']}")
    return 0 if reply["status"] == 0 else 1


def cmd_scan(client, args):
    module_base = find_module_base(client)
    if not module_base:
        print("[!] cannot find module base")
        return 1
    print(f"[+] module base: 0x{module_base:X}")

    pe_data = client.read(module_base, 0x1000)
    pe = parse_pe_header(pe_data, module_base)
    if not pe:
        print("[!] PE parse failed")
        return 1

    print(f"[+] size of image: 0x{pe.size_of_image:X}")
    print(f"[+] sections:")
    for s in pe.sections:
        flags = ""
        if s.is_readable:
            flags += "R"
        if s.is_writable:
            flags += "W"
        if s.is_executable:
            flags += "X"
        print(f"    {s.name:8s}  VA=0x{s.virtual_addr:X}  Size=0x{s.virtual_size:X}  {flags}")

    data_sec = pe.find_section_by_name(".data")
    if data_sec:
        print(f"\n[+] .data section at RVA=0x{data_sec.virtual_addr:X} size=0x{data_sec.virtual_size:X}")
    return 0


def cmd_probe(client, args):
    gnames = int(args.gnames, 16)
    struct_addr = int(args.struct_addr, 16)
    struct_name = args.name
    child_off = int(args.child_offset, 16) if args.child_offset else 0x68
    use_pool = not args.name_array

    resolver = NameResolver(client, gnames, use_pool=use_pool)
    test = resolver.resolve(gnames)
    if test:
        print(f"[+] name resolution OK, test: '{test}'")
    else:
        print("[!] name resolution failed, try --name-array")
        return 1

    print(f"\n[*] probing FField offsets for {struct_name} @ 0x{struct_addr:X}...")
    result = probe_ffield_offsets(client, resolver, struct_addr, child_off)
    if not result or not result.is_valid():
        print("[!] probe failed")
        return 1

    print(f"  FField::Class = 0x{result.ffield_class:X}")
    print(f"  FField::Name  = 0x{result.ffield_name:X}")
    print(f"  FField::Next  = 0x{result.ffield_next:X}")

    fields = walk_ffield_chain(
        client, resolver, struct_addr, child_off,
        result.ffield_next, result.ffield_name, result.ffield_class
    )
    print(f"\n[+] {len(fields)} fields:")
    for i, f in enumerate(fields):
        print(f"  [{i:2d}] 0x{f.address:X}  name='{f.field_name}'  class='{f.class_name}'")

    names = [f.field_name for f in fields if f.field_name]
    unique = set(names)
    if len(unique) < len(names):
        print("\n[!!!] NAME DUPLICATION DETECTED")
    return 0


def cmd_globals(client, args):
    modules = client.enum_modules()
    if not modules:
        print("[!] cannot enumerate modules")
        return 1

    game_mod = None
    for m in modules:
        if m["name"].lower() == "htgame.exe":
            game_mod = m
            break
    if not game_mod:
        non_sys = [m for m in modules if not m["name"].lower().endswith(".dll")]
        if non_sys:
            game_mod = non_sys[0]
    if not game_mod:
        print("[!] cannot find game module")
        return 1

    base = game_mod["base"]
    print(f"[+] game module: {game_mod['name']} @ 0x{base:016X}")

    pe_data = client.read(base, 0x1000)
    pe = parse_pe_header(pe_data, base)
    if not pe:
        print("[!] PE parse failed")
        return 1

    text_sec = pe.find_section_by_name(".text")
    data_sec = pe.find_section_by_name(".data")

    if text_sec:
        text_rva = text_sec.virtual_addr
        text_size = min(text_sec.virtual_size, 0x2000000)
        print(f"[*] reading .text section: RVA=0x{text_rva:X} size=0x{text_size:X}")
        text_data = client.read(base + text_rva, text_size)
        if text_data:
            gnames_cands = find_gnames_by_signature(text_data, text_rva, base)
            print(f"\n[+] GNames candidates ({len(gnames_cands)}):")
            for i, c in enumerate(gnames_cands[:20]):
                print(f"  [{i:2d}] insn=0x{c['insn_addr']:016X}  target=0x{c['lea_target']:016X}  type={c['type']}")
        else:
            print("[!] failed to read .text section")

    if data_sec:
        data_rva = data_sec.virtual_addr
        data_size = min(data_sec.virtual_size, 0x1000000)
        print(f"\n[*] reading .data section: RVA=0x{data_rva:X} size=0x{data_size:X}")
        data_data = client.read(base + data_rva, data_size)
        if data_data:
            gobj_cands = find_gobjects_in_data(data_data, data_rva, base)
            print(f"\n[+] GObjects candidates ({len(gobj_cands)}):")
            for i, c in enumerate(gobj_cands[:20]):
                if c["layout"] == "chunked_default":
                    print(f"  [{i:2d}] 0x{c['address']:016X}  num={c['num_elements']}  max={c['max_elements']}  chunks={c['num_chunks']}/{c['max_chunks']}  layout=chunked")
                else:
                    print(f"  [{i:2d}] 0x{c['address']:016X}  num={c['num_elements']}  max={c['max_elements']}  layout=fixed")

            ptrs = scan_data_pointers(data_data, data_rva, base)
            print(f"\n[+] data pointers in game address space: {len(ptrs)}")
        else:
            print("[!] failed to read .data section")

    return 0


def main():
    parser = argparse.ArgumentParser(description="WinHttpRedirectProxy IPC Diagnostics")
    parser.add_argument("pid", type=int, help="Target process PID")
    sub = parser.add_subparsers(dest="command")

    p_read = sub.add_parser("read", help="Read and dump memory")
    p_read.add_argument("addr", help="Address (hex)")
    p_read.add_argument("size", help="Size (hex)")

    sub.add_parser("modules", help="List loaded modules via PEB")

    p_load = sub.add_parser("load", help="Load a DLL inside the target through memory IPC")
    p_load.add_argument("dll", help="DLL path")

    sub.add_parser("scan", help="Scan PE header and sections")

    sub.add_parser("globals", help="Scan for UE global variables (GNames/GObjects)")

    p_probe = sub.add_parser("probe", help="Probe UE FField offsets")
    p_probe.add_argument("--gnames", required=True, help="GNames address (hex)")
    p_probe.add_argument("--struct-addr", required=True, help="UStruct address (hex)")
    p_probe.add_argument("--name", default="Unknown", help="Struct name")
    p_probe.add_argument("--child-offset", help="ChildProperties offset (hex, default 0x68)")
    p_probe.add_argument("--name-array", action="store_true", help="Use NameArray instead of NamePool")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    client = IpcClient(args.pid)
    if not client.is_connected():
        print(f"[!] failed to connect to PID {args.pid}")
        return 1
    print(f"[+] connected to PID {args.pid}")

    try:
        handlers = {
            "read": cmd_read,
            "modules": cmd_modules,
            "load": cmd_load,
            "scan": cmd_scan,
            "globals": cmd_globals,
            "probe": cmd_probe,
        }
        return handlers[args.command](client, args)
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
