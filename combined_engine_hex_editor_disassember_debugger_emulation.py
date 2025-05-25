#!/usr/bin/env python3
import sys
import argparse
import re
import string
import math
import os
import subprocess
import lief
from lief import PE, ELF
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import cxxfilt

sys.set_int_max_str_digits(999999999)

def binary_viewer_for_ints(number):
    return bin(number)[2:]

def utf8_to_binary(text):
    return ' '.join(format(b, '08b') for b in text.encode('utf-8'))

def view_binary_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            while True:
                b = f.read(1)
                if not b:
                    break
                print(b.hex(), end=' ')
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")

def write_binary_file(file_path, data_bytes):
    with open(file_path, 'wb') as f:
        f.write(data_bytes)

def inject_binary_file(file_path, data_bytes, offset):
    try:
        with open(file_path, 'rb') as f:
            orig = f.read()
        with open(file_path, 'wb') as f:
            f.write(orig[:offset] + data_bytes + orig[offset:])
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")

def parse_hex_data(data_str):
    data_str = data_str.replace('0x', '').replace(' ', '')
    if len(data_str) % 2:
        data_str = '0' + data_str
    return bytes.fromhex(data_str)

def print_info(file_path):
    b = lief.parse(file_path)
    fmt = b.format.name
    if fmt == 'ELF':
        arch = b.header.machine_type.name
        bits = b.header.identity_class.name
    elif fmt == 'PE':
        arch = b.header.machine.name
        bits = 'PE32' if b.header.optional_header.magic == PE.PE_TYPE.PE32 else 'PE32+'
    else:
        arch = b.header.cpu_type.name
        bits = '32-bit' if b.header.is_32 else '64-bit'
    print(f"Format: {fmt}")
    print(f"Architecture: {arch}")
    print(f"Type: {bits}")
    print(f"Endianness: {b.header.endianness.name}")
    print(f"Entry point: 0x{b.entrypoint:x}")
    print(f"Sections: {len(b.sections)}")
    print(f"Symbols: {len(b.symbols)}")

def list_sections(file_path):
    b = lief.parse(file_path)
    for s in b.sections:
        perms = ''.join(p for p in s.permissions.name if p.isupper())
        print(f"{s.name}\t0x{s.virtual_address:x}\t0x{s.size:x}\t{perms}")

def list_symbols(file_path):
    b = lief.parse(file_path)
    for sym in b.symbols:
        print(f"{sym.name}\t0x{sym.value:x}\t{sym.size}")

def list_imports(file_path):
    b = lief.parse(file_path)
    for lib in b.imports:
        print(lib.name)
        for entry in lib.entries:
            print(f"  {entry.name}")

def list_exports(file_path):
    b = lief.parse(file_path)
    for exp in b.exported_functions:
        print(exp)

def extract_strings(file_path, min_len):
    with open(file_path, 'rb') as f:
        data = f.read()
    pattern = re.compile(rb'[' + re.escape(bytes(string.printable, 'ascii')) + rb']{' + str(min_len).encode() + rb',}')
    for m in pattern.finditer(data):
        print(m.group().decode('ascii', errors='ignore'))

def hexdump(file_path, width):
    with open(file_path, 'rb') as f:
        offset = 0
        while chunk := f.read(width):
            hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
            ascii_bytes = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"{offset:08x}  {hex_bytes:<{width*3}}  {ascii_bytes}")
            offset += width

def search_pattern(file_path, pattern, is_hex):
    with open(file_path, 'rb') as f:
        data = f.read()
    pat = parse_hex_data(pattern) if is_hex else pattern.encode()
    start = 0
    while True:
        idx = data.find(pat, start)
        if idx < 0:
            break
        print(f"0x{idx:x}")
        start = idx + 1

def disassemble(file_path, offset, length, section, mode):
    b = lief.parse(file_path)
    with open(file_path, 'rb') as f:
        blob = f.read()
    if section:
        sec = next((s for s in b.sections if s.name == section), None)
        if not sec:
            print(f"Section '{section}' not found.")
            return
        code = bytes(sec.content)
        addr = sec.virtual_address
    elif offset is not None:
        addr = offset
        code = blob[offset:offset+length] if length else blob[offset:]
    else:
        sec = next((s for s in b.sections if s.name.lower() in ('.text','__text','text')), None)
        if not sec:
            print("No .text section found and no offset provided.")
            return
        code = bytes(sec.content)
        addr = sec.virtual_address
    cs_mode = CS_MODE_64 if mode == '64' else CS_MODE_32
    md = Cs(CS_ARCH_X86, cs_mode)
    for insn in md.disasm(code, addr):
        print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")

def patch_binary_file(file_path, data_bytes, offset):
    try:
        with open(file_path, 'rb') as f:
            orig = f.read()
        with open(file_path, 'wb') as f:
            f.write(orig[:offset] + data_bytes + orig[offset+len(data_bytes):])
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")

def list_relocations(file_path):
    b = lief.parse(file_path)
    rels = getattr(b, 'relocations', None) or getattr(b, 'pltgot_relocations', None)
    if rels:
        for r in rels:
            addr = getattr(r, 'address', None) or getattr(r, 'rva', None)
            typ = getattr(r, 'type', None)
            tname = typ.name if hasattr(typ, 'name') else typ
            print(f"0x{addr:x}:\t{tname}")
    else:
        print("No relocations found.")

def list_tls(file_path):
    b = lief.parse(file_path)
    if b.format == lief.EXE_FORMATS.PE and b.has_tls:
        tls = b.tls
        if tls and tls.callbacks:
            for cb in tls.callbacks:
                print(f"0x{cb:x}")
        else:
            print("No TLS callbacks.")
    elif b.format == lief.EXE_FORMATS.ELF:
        for entry in b.dynamic_entries:
            if entry.tag == lief.ELF.DYNAMIC_TAGS.INIT_ARRAY:
                for addr in entry.array:
                    print(f"0x{addr:x}")
    else:
        print("No TLS information.")

def list_overlay(file_path):
    b = lief.parse(file_path)
    with open(file_path, 'rb') as f:
        data = f.read()
    last = 0
    for s in b.sections:
        end = s.file_offset + len(s.content)
        if end > last:
            last = end
    overlay = data[last:]
    if overlay:
        print(overlay.hex())
    else:
        print("No overlay data.")

def entropy(data):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = -sum((cnt/len(data)) * math.log2(cnt/len(data)) for cnt in freq.values())
    return ent

def calc_entropy(file_path, min_size):
    with open(file_path, 'rb') as f:
        data = f.read()
    if len(data) < min_size:
        print("File too small for entropy analysis.")
        return
    print(f"Entropy: {entropy(data):.4f}")

def entropy_sections(file_path):
    b = lief.parse(file_path)
    for s in b.sections:
        data = bytes(s.content)
        print(f"{s.name}:\t{entropy(data):.4f}")

def call_graph(file_path, mode):
    b = lief.parse(file_path)
    with open(file_path, 'rb') as f:
        blob = f.read()
    sec = next((s for s in b.sections if s.name.lower() in ('.text','__text','text')), None)
    if not sec:
        print("No .text section found.")
        return
    code = bytes(sec.content)
    addr = sec.virtual_address
    cs_mode = CS_MODE_64 if mode == '64' else CS_MODE_32
    md = Cs(CS_ARCH_X86, cs_mode)
    graph = {}
    for insn in md.disasm(code, addr):
        if insn.mnemonic.startswith('call'):
            op = insn.op_str.strip()
            if op.startswith('0x'):
                target = int(op, 16)
                src = next((sym.name or hex(sym.value) for sym in b.symbols if sym.value <= insn.address < sym.value+sym.size), hex(insn.address))
                dst = next((sym.name or hex(sym.value) for sym in b.symbols if sym.value == target), hex(target))
                graph.setdefault(src, set()).add(dst)
    for src, dsts in graph.items():
        for d in dsts:
            print(f"{src} -> {d}")

def list_program_headers(file_path):
    b = lief.parse(file_path)
    for ph in getattr(b, 'segments', []):
        flags = ','.join(ph.flags_list) if hasattr(ph, 'flags_list') else ''
        print(f"{ph.type.name}\t0x{ph.file_offset:x}\t0x{ph.virtual_address:x}\t0x{ph.physical_address:x}\t0x{ph.file_size:x}\t0x{ph.virtual_size:x}\t{flags}")

def list_dynamic_entries(file_path):
    b = lief.parse(file_path)
    for entry in getattr(b, 'dynamic_entries', []):
        tag = entry.tag.name
        val = entry.value if hasattr(entry, 'value') else getattr(entry, 'size', '')
        if isinstance(val, int):
            print(f"{tag}\t0x{val:x}")
        else:
            print(f"{tag}\t{val}")

def extract_unicode_strings(file_path, min_len):
    with open(file_path, 'rb') as f:
        data = f.read()
    pat_le = re.compile(b'(?:[ -~]\x00){' + str(min_len).encode() + b',}')
    pat_be = re.compile(b'(?:\x00[ -~]){' + str(min_len).encode() + b',}')
    for m in pat_le.finditer(data):
        print(m.group().decode('utf-16-le', errors='ignore'))
    for m in pat_be.finditer(data):
        print(m.group().decode('utf-16-be', errors='ignore'))

def list_xrefs(file_path, symbol_name):
    b = lief.parse(file_path)
    sym = next((s for s in b.symbols if s.name == symbol_name), None)
    if not sym:
        print(f"Symbol '{symbol_name}' not found.")
        return
    addr = sym.value
    bits = 64 if (b.header.identity_class.name == 'ELFCLASS64' if b.format.name == 'ELF' else b.header.optional_header.magic == PE.PE_TYPE.PE32_PLUS) else 32
    size = bits // 8
    pattern = addr.to_bytes(size, 'little')
    with open(file_path, 'rb') as f:
        data = f.read()
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx < 0:
            break
        print(f"0x{idx:x}")
        start = idx + 1

def compare_binaries(file1, file2):
    for fp in (file1, file2):
        b = lief.parse(fp)
        fmt = b.format.name
        if fmt == 'ELF':
            arch = b.header.machine_type.name
            bits = b.header.identity_class.name
        elif fmt == 'PE':
            arch = b.header.machine.name
            bits = 'PE32' if b.header.optional_header.magic == PE.PE_TYPE.PE32 else 'PE32+'
        else:
            arch = b.header.cpu_type.name
            bits = '32-bit' if b.header.is_32 else '64-bit'
        print(f"{fp}: Format {fmt}, Arch {arch}, Type {bits}, Entry 0x{b.entrypoint:x}, Sections {len(b.sections)}, Symbols {len(b.symbols)}")

def control_flow_graph(file_path, func, mode):
    b = lief.parse(file_path)
    entry = None; size = None
    if func.startswith('0x'):
        entry = int(func, 16)
        sym = next((s for s in b.symbols if s.value == entry), None)
        size = sym.size if sym else None
    else:
        sym = next((s for s in b.symbols if s.name == func), None)
        if sym:
            entry = sym.value
            size = sym.size
    if entry is None:
        print("Function not found.")
        return
    sec = next((s for s in b.sections if s.virtual_address <= entry < s.virtual_address + len(s.content)), None)
    if not sec:
        print("Section not found.")
        return
    offset = entry - sec.virtual_address
    code = bytes(sec.content)[offset:(offset + size) if size else None]
    addr = sec.virtual_address
    cs_mode = CS_MODE_64 if mode == '64' else CS_MODE_32
    md = Cs(CS_ARCH_X86, cs_mode)
    insns = list(md.disasm(code, entry))
    boundaries = {entry}
    for insn in insns:
        op = insn.op_str.strip()
        if op.startswith('0x'):
            tgt = int(op, 16)
            boundaries.add(tgt)
            boundaries.add(insn.address + insn.size)
        if insn.mnemonic in ('ret', 'retq'):
            boundaries.add(insn.address + insn.size)
    boundaries = sorted(x for x in boundaries if entry <= x < (entry + size) if size else True)
    blocks = []
    for i, start in enumerate(boundaries):
        end = boundaries[i+1] if i+1 < len(boundaries) else (entry + size if size else None)
        blocks.append((start, end))
    succ = {}
    for start, end in blocks:
        succ[start] = []
        last = next((i for i in reversed(insns) if start <= i.address < (end or float('inf'))), None)
        if not last: continue
        if last.mnemonic.startswith('j'):
            op = last.op_str.strip()
            if op.startswith('0x'):
                succ[start].append(int(op, 16))
            if last.mnemonic not in ('jmp',):
                fall = last.address + last.size
                succ[start].append(fall)
        elif last.mnemonic in ('ret', 'retq'):
            pass
        else:
            fall = last.address + last.size
            succ[start].append(fall)
    print("digraph CFG {")
    for s, _ in blocks:
        print(f'"{hex(s)}" [label="{hex(s)}"];')
    for s, dests in succ.items():
        for d in dests:
            print(f'"{hex(s)}" -> "{hex(d)}";')
    print("}")

# extended features

def demangle(name):
    try:
        return cxxfilt.demangle(name)
    except:
        return name

def list_functions(file_path):
    b = lief.parse(file_path)
    for sym in b.symbols:
        if hasattr(sym, 'type') and sym.type == ELF.SYMBOL_TYPES.FUNC:
            print(f"{sym.name}\t0x{sym.value:x}\t{sym.size}")

def xref_strings(file_path, min_len):
    with open(file_path, 'rb') as f:
        data = f.read()
    pattern = re.compile(rb'[' + re.escape(bytes(string.printable, 'ascii')) + rb']{' + str(min_len).encode() + rb',}')
    for m in pattern.finditer(data):
        s = m.group().decode('ascii', errors='ignore')
        print(f"{s}:")
        start = 0
        while True:
            idx = data.find(m.group(), start)
            if idx < 0:
                break
            print(f"  0x{idx:x}")
            start = idx + 1

def rebase(file_path, new_base, output):
    b = lief.parse(file_path)
    if b.format == lief.EXE_FORMATS.PE:
        b.optional_header.imagebase = new_base
    elif b.format == lief.EXE_FORMATS.ELF:
        b.header.entrypoint = new_base - b.optional_header.imagebase + b.entrypoint
        b.optional_header.imagebase = new_base
    b.write(output)

def decompile(file_path, func, script, project_dir, ghidra_path):
    headless = os.path.join(ghidra_path, 'support', 'analyzeHeadless')
    args = [headless, project_dir, project_dir + '_out', '-import', file_path, '-postScript', script, func]
    subprocess.run(args)

def main():
    parser = argparse.ArgumentParser(prog='ghidra_alt', description='Binary analysis tool')
    subparsers = parser.add_subparsers(dest='cmd', required=True)

    p_int = subparsers.add_parser('int')
    p_int.add_argument('number', type=int)

    p_utf8 = subparsers.add_parser('utf8')
    p_utf8.add_argument('text', type=str)

    p_view = subparsers.add_parser('view')
    p_view.add_argument('file', type=str)

    p_write = subparsers.add_parser('write')
    p_write.add_argument('file', type=str)
    p_write.add_argument('data', type=str)

    p_inject = subparsers.add_parser('inject')
    p_inject.add_argument('file', type=str)
    p_inject.add_argument('data', type=str)
    p_inject.add_argument('offset', type=int)

    p_info = subparsers.add_parser('info')
    p_info.add_argument('file', type=str)

    p_sections = subparsers.add_parser('sections')
    p_sections.add_argument('file', type=str)

    p_symbols = subparsers.add_parser('symbols')
    p_symbols.add_argument('file', type=str)

    p_imports = subparsers.add_parser('imports')
    p_imports.add_argument('file', type=str)

    p_exports = subparsers.add_parser('exports')
    p_exports.add_argument('file', type=str)

    p_strings = subparsers.add_parser('strings')
    p_strings.add_argument('file', type=str)
    p_strings.add_argument('-n', '--min', type=int, default=4)

    p_hexdump = subparsers.add_parser('hexdump')
    p_hexdump.add_argument('file', type=str)
    p_hexdump.add_argument('-n', '--width', type=int, default=16)

    p_search = subparsers.add_parser('search')
    grp = p_search.add_mutually_exclusive_group(required=True)
    grp.add_argument('-x', '--hex', dest='hex', action='store_true')
    grp.add_argument('-s', '--string', dest='string', action='store_true')
    p_search.add_argument('file', type=str)
    p_search.add_argument('pattern', type=str)

    p_disasm = subparsers.add_parser('disasm')
    p_disasm.add_argument('file', type=str)
    p_disasm.add_argument('-o', '--offset', type=lambda x: int(x, 0), default=None)
    p_disasm.add_argument('-l', '--length', type=int, default=0)
    p_disasm.add_argument('-s', '--section', type=str, default=None)
    p_disasm.add_argument('-m', '--mode', choices=('32', '64'), default='64')

    p_patch = subparsers.add_parser('patch')
    p_patch.add_argument('file', type=str)
    p_patch.add_argument('data', type=str)
    p_patch.add_argument('offset', type=int)

    p_relocs = subparsers.add_parser('relocations')
    p_relocs.add_argument('file', type=str)

    p_tls = subparsers.add_parser('tls')
    p_tls.add_argument('file', type=str)

    p_overlay = subparsers.add_parser('overlay')
    p_overlay.add_argument('file', type=str)

    p_entropy = subparsers.add_parser('entropy')
    p_entropy.add_argument('file', type=str)
    p_entropy.add_argument('-n', '--min', type=int, default=0)

    p_entropy_sec = subparsers.add_parser('entropy-sections')
    p_entropy_sec.add_argument('file', type=str)

    p_callgraph = subparsers.add_parser('callgraph')
    p_callgraph.add_argument('file', type=str)
    p_callgraph.add_argument('-m', '--mode', choices=('32', '64'), default='64')

    p_phdrs = subparsers.add_parser('phdrs')
    p_phdrs.add_argument('file', type=str)

    p_dynamic = subparsers.add_parser('dynamic')
    p_dynamic.add_argument('file', type=str)

    p_unicode = subparsers.add_parser('unicode-strings')
    p_unicode.add_argument('file', type=str)
    p_unicode.add_argument('-n', '--min', type=int, default=4)

    p_xrefs = subparsers.add_parser('xrefs')
    p_xrefs.add_argument('file', type=str)
    p_xrefs.add_argument('symbol', type=str)

    p_compare = subparsers.add_parser('compare')
    p_compare.add_argument('file1', type=str)
    p_compare.add_argument('file2', type=str)

    p_cfg = subparsers.add_parser('cfg')
    p_cfg.add_argument('file', type=str)
    p_cfg.add_argument('func', type=str)
    p_cfg.add_argument('-m', '--mode', choices=('32', '64'), default='64')

    # extended commands
    p_demangle = subparsers.add_parser('demangle')
    p_demangle.add_argument('name', type=str)

    p_functions = subparsers.add_parser('functions')
    p_functions.add_argument('file', type=str)

    p_xrefstr = subparsers.add_parser('xref-strings')
    p_xrefstr.add_argument('file', type=str)
    p_xrefstr.add_argument('-n', '--min', type=int, default=4)

    p_rebase = subparsers.add_parser('rebase')
    p_rebase.add_argument('file', type=str)
    p_rebase.add_argument('base', type=lambda x: int(x, 0))
    p_rebase.add_argument('output', type=str)

    p_decompile = subparsers.add_parser('decompile')
    p_decompile.add_argument('file', type=str)
    p_decompile.add_argument('func', type=str)
    p_decompile.add_argument('script', type=str)
    p_decompile.add_argument('project', type=str)
    p_decompile.add_argument('ghidra_home', type=str)

    args = parser.parse_args()

    if args.cmd == 'int':
        print(binary_viewer_for_ints(args.number))
    elif args.cmd == 'utf8':
        print(utf8_to_binary(args.text))
    elif args.cmd == 'view':
        view_binary_file(args.file)
    elif args.cmd == 'write':
        write_binary_file(args.file, parse_hex_data(args.data))
    elif args.cmd == 'inject':
        inject_binary_file(args.file, parse_hex_data(args.data), args.offset)
    elif args.cmd == 'info':
        print_info(args.file)
    elif args.cmd == 'sections':
        list_sections(args.file)
    elif args.cmd == 'symbols':
        list_symbols(args.file)
    elif args.cmd == 'imports':
        list_imports(args.file)
    elif args.cmd == 'exports':
        list_exports(args.file)
    elif args.cmd == 'strings':
        extract_strings(args.file, args.min)
    elif args.cmd == 'hexdump':
        hexdump(args.file, args.width)
    elif args.cmd == 'search':
        search_pattern(args.file, args.pattern, args.hex)
    elif args.cmd == 'disasm':
        disassemble(args.file, args.offset, args.length, args.section, args.mode)
    elif args.cmd == 'patch':
        patch_binary_file(args.file, parse_hex_data(args.data), args.offset)
    elif args.cmd == 'relocations':
        list_relocations(args.file)
    elif args.cmd == 'tls':
        list_tls(args.file)
    elif args.cmd == 'overlay':
        list_overlay(args.file)
    elif args.cmd == 'entropy':
        calc_entropy(args.file, args.min)
    elif args.cmd == 'entropy-sections':
        entropy_sections(args.file)
    elif args.cmd == 'callgraph':
        call_graph(args.file, args.mode)
    elif args.cmd == 'phdrs':
        list_program_headers(args.file)
    elif args.cmd == 'dynamic':
        list_dynamic_entries(args.file)
    elif args.cmd == 'unicode-strings':
        extract_unicode_strings(args.file, args.min)
    elif args.cmd == 'xrefs':
        list_xrefs(args.file, args.symbol)
    elif args.cmd == 'compare':
        compare_binaries(args.file1, args.file2)
    elif args.cmd == 'cfg':
        control_flow_graph(args.file, args.func, args.mode)
    elif args.cmd == 'demangle':
        print(demangle(args.name))
    elif args.cmd == 'functions':
        list_functions(args.file)
    elif args.cmd == 'xref-strings':
        xref_strings(args.file, args.min)
    elif args.cmd == 'rebase':
        rebase(args.file, args.base, args.output)
    elif args.cmd == 'decompile':
        decompile(args.file, args.func, args.script, args.project, args.ghidra_home)

if __name__ == '__main__':
    main()
