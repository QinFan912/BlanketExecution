import binascii
import os
import subprocess
import sys
from struct import *
import pprint
from collections import defaultdict

from variable_recover.address_extractor import VariablesAddressExtractor

import angr
from angr.sim_variable import SimRegisterVariable, SimStackVariable


def main(argv):
    base_addr = 0x4000000

    file_name = "rm"

    # X86
    X86_file_path = "/home/qinfan/coreutils/coreutils-X86/src/" + file_name

    # ARM32
    ARM32_file_path = "/home/qinfan/coreutils/coreutils-ARM32/src/" + file_name

    # ARM64
    ARM64_file_path = "/home/qinfan/coreutils/coreutils-ARM64/src/" + file_name

    # MIPS32
    MIPS32_file_path = "/home/qinfan/coreutils/coreutils-MIPS32/src/" + file_name

    # MIPS64
    MIPS64_file_path = "/home/qinfan/coreutils/coreutils-MIPS64/src/" + file_name

    p = angr.Project(X86_file_path, auto_load_libs=False,
                     load_options={
                         'main_opts': {
                             'base_addr': base_addr
                         }
                     })

    l = [67118843, 67119051, 67119730, 69279760, 69279768, 69279944, 69279960, 69279968, 69280000]

    print(p.loader.min_addr)
    print(p.loader.max_addr)

    res = []
    for v in l:
        ob = p.loader.find_object_containing(v)
        if ob:
            se = ob.find_section_containing(v)
            print(se)
            print(se.type)
        # if '.data' in str(se):
        init_state = p.factory.blank_state(addr=v, mode="fastpath",
                                           add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC,
                                                        angr.options.CALLLESS,
                                                        angr.options.LAZY_SOLVES})

        a = init_state.solver.eval(init_state.memory.load(v, size=4), cast_to=bytes)
        print(a)
        # c = init_state.mem[v].deref.string.concrete
        # print(c.decode())

        # a = b'\x9c\x8e\x01\x00'
        b = int.from_bytes(a, byteorder='little', signed=True)
        print(b)
        if p.loader.min_addr <= b <= p.loader.max_addr:
            init_state = p.factory.blank_state(addr=b, mode="fastpath",
                                               add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC,
                                                            angr.options.CALLLESS,
                                                            angr.options.LAZY_SOLVES})
            try:
                c = init_state.solver.eval(init_state.memory.load(b, size=4), cast_to=bytes)
                print(c)
                d = c.decode().strip('\x00')
                print(d)
                if d:
                    res.append(d)
                    print(d)
            except:
                print("error")
    print(res)


if __name__ == "__main__":
    main(sys.argv)
