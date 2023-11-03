#!/usr/bin/env python3

import os
import pathlib
import shutil
import sys
from dataclasses import dataclass


@dataclass
class Segment:
    """An ELF segment parsed from a `/proc/<PID>/map` file.

    See: https://www.baeldung.com/linux/proc-id-maps"""

    start_vaddr: str
    end_vaddr: str
    flags: str
    file_offset: str
    dev_id: str
    inode: int
    file: str


def usage():
    print("usage: pt_standalone.py <name> <trace-file> <map-file>\n")
    print("where:")
    print("  <name> is used to name the output files")
    print("  <trace-file> is a file containing the raw PT packets")
    print("  <map-file> is the /proc/<PID>/map file for the traced process")


def fatal(msg):
    print(f"fatal: {msg}")
    sys.exit(1)


def parse_map(map_handle):
    num = 0
    segs = []
    for line in map_handle:
        num += 1
        elems = line.split()
        if len(elems) not in (5, 6):
            fatal(f"parse error in map file, line {num}: "
                  "wrong number of fields")

        if len(elems) == 5:
            # Then the segment has no file field, which is OK.
            elems.append("")

        (vaddrs, flags, file_offset, dev_id, inode, file) = elems

        vaddr_elems = vaddrs.split("-")
        if len(vaddr_elems) != 2:
            fatal(f"parse error in map file, line {num}: "
                  "vaddrs field malformed")

        seg = Segment(start_vaddr=vaddr_elems[0], end_vaddr=vaddr_elems[1],
                      flags=flags, file_offset=file_offset, dev_id=dev_id,
                      inode=inode, file=file)
        segs.append(seg)

    return segs


def gen(name, trace_file, map_file):
    with open(map_file) as map_handle:
        segs = parse_map(map_handle)

    script_name = f"decode_{name}.sh"
    decode_script = open(script_name, "w")
    decode_script.write("#!/bin/sh\n\n")
    decode_script.write("ptxed \\\n")

    obj_dir = f"obj_{name}"
    for seg in segs:
        # We can only provide segments that came from the filesystem.
        # FIXME: Add VDSO.
        if not seg.file.startswith("/"):
            continue
        # We only care about executable segments.
        if 'x' not in seg.flags:
            continue

        copy_dest = obj_dir + os.sep + seg.file
        pathlib.Path(os.path.dirname(copy_dest)).mkdir(
                parents=True, exist_ok=True)
        if not os.path.exists(copy_dest):
            shutil.copyfile(seg.file, copy_dest)

        decode_script.write(
                "\t--raw "
                f"{copy_dest}:0x{seg.file_offset}:0x{seg.start_vaddr} \\\n")

    decode_script.write(f"\t--pt {trace_file}\n")
    decode_script.close()

    print("All good. I generated:")
    print(f"  - {script_name}")
    print(f"  - {obj_dir}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        usage()
        sys.exit(1)
    else:
        gen(*sys.argv[1:])
