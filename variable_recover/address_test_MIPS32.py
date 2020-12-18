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

    p = angr.Project(MIPS32_file_path, auto_load_libs=False,
                     load_options={
                         'main_opts': {
                             'base_addr': base_addr
                         }
                     })

    l = [4204908, 4205072, 4205268, 4282544, 4282728, 4282752, 4284968, 4284972, 4285012, 4285032,
         4285088, 4285092, 4285200, 4285208, 4285224, 4285260, 4285300, 4285340, 4285368, 4285396,
         4285408, 4285432, 4357880, 4359000, 4359104, 4391136]

    print(p.loader.min_addr)
    print(p.loader.max_addr)

    res = []
    for v in l:
        ob = p.loader.find_object_containing(v)
        if ob:
            se = ob.find_section_containing(v)
            print(se)
            print(se.type)
        init_state = p.factory.blank_state(addr=v, mode="fastpath",
                                           add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC,
                                                        angr.options.CALLLESS,
                                                        angr.options.LAZY_SOLVES})

        try:
            a = init_state.solver.eval(init_state.memory.load(v, size=100), cast_to=bytes)
            print(a)
            d = a.decode().strip('\x00').replace('\x00', ' ')
            if d:
                res.append(d)
        except:
            print("error")

    print(res)


if __name__ == "__main__":
    main(sys.argv)
