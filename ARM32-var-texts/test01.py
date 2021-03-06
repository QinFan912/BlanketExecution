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

    p = angr.Project(ARM32_file_path, auto_load_libs=False,
                     load_options={
                         'main_opts': {
                             'base_addr': base_addr
                         }
                     })

    print(p.arch.memory_endness)

    '''
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
    '''

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

    l = [40004, 40224, 40348, 40956, 40960, 40964, 40972, 40976, 40980, 40988, 40992, 40996,
         41000, 41004, 41008, 41012, 41016, 41020, 41024, 41044, 41048, 41052, 41056, 41060,
         41064, 41068, 41076, 41080, 41084, 41088, 41092]

    # l = [67118843, 67119051, 67119730, 69279760, 69279768, 69279944, 69279960, 69279968, 69280000]

    # l = [4204908, 4205072, 4205268, 4282544, 4282728, 4282752, 4284968, 4284972, 4285012, 4285032,
    #      4285088, 4285092, 4285200, 4285208, 4285224, 4285260, 4285300, 4285340, 4285368, 4285396,
    #      4285408, 4285432, 4357880, 4359000, 4359104, 4391136]

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

        try:
            a = init_state.solver.eval(init_state.memory.load(v, size=4), cast_to=bytes)
            print(a)
        except:
            print("error")
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

    print(p.arch.memory_endness)


if __name__ == "__main__":
    main(sys.argv)
