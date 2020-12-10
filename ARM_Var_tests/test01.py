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

    # x = 1668444006
    # x = 1702258030
    x = 1852143205
    # x = 1718579811

    command = "readelf -h " + MIPS32_file_path
    back = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    print(back[0].decode())

    if 'little endian' in back[0].decode():
        y = x.to_bytes(4, byteorder='little')
        print(y.decode())
    else:
        y = x.to_bytes(4, byteorder='big')
        print(y.decode())

    # addr = 69279760
    #
    # a = p.loader.describe_addr(addr)
    # print(a)
    #
    # ob = p.loader.find_object_containing(addr)
    # se = ob.find_section_containing(addr)
    # print(se)
    # print(se.type)
    # print(se.is_readable)
    # print(se.is_writable)
    # print(se.is_executable)

    # s = p.kb.xrefs.get_xrefs_by_dst(dst=40004)
    # print(s)


'''
    l = [40004, 40224, 40348, 40956, 40960, 40964, 40972, 40976, 40980, 40988, 40992, 40996,
         41000, 41004, 41008, 41012, 41016, 41020, 41024, 41044, 41048, 41052, 41056, 41060,
         41064, 41068, 41076, 41080, 41084, 41088, 41092]

    l = [67118843, 67119051, 67119730, 69279760, 69279768, 69279944, 69279960, 69279968, 69280000]

    for v in l:
        ob = p.loader.find_object_containing(v)
        se = ob.find_section_containing(v)
        print(se)
        print(se.type)
        if '.data' in str(se):
            init_state = p.factory.blank_state(addr=v, mode="fastpath",
                                               add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC,
                                                            angr.options.CALLLESS,
                                                            angr.options.LAZY_SOLVES})

            # c = init_state.solver.eval(init_state.memory.load(v, size=4), cast_to=bytes)
            c = init_state.mem[v].deref.string.concrete
            # print(c.decode())
            print(c)

'''

if __name__ == "__main__":
    main(sys.argv)
