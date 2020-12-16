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

    min_addr = p.loader.min_addr
    max_addr = p.loader.max_addr
    print("min_addr:", min_addr)
    print("max_addr:", max_addr)

    cfg = p.analyses.CFG(show_progressbar=True, data_references=True, normalize=True)
    mem_data = cfg.memory_data

    cc = p.analyses.CompleteCallingConventions(recover_variables=True)
    gvar = p.kb.variables['global']._variables
    gvar_dict = defaultdict(list)
    print("global variables:", gvar)

    kb = angr.KnowledgeBase(p)
    funcs = list(cfg.kb.functions.values())
    function_numbers = len(funcs)
    print("function_numbers:", function_numbers)

    for func in cfg.kb.functions.values():
        if func.is_simprocedure or func.is_plt:
            # skil all SimProcedures and PLT stubs
            continue
        if func.alignment:
            # skil all aligement functions
            continue

        if func.name != 'main':
            continue

        init_state = p.factory.blank_state(addr=func.addr, mode="fastpath",
                                           add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC,
                                                        angr.options.CALLLESS,
                                                        angr.options.LAZY_SOLVES})

        stack_base_addr = init_state.regs.sp
        print(stack_base_addr)

        sm = p.factory.simgr(init_state, save_unsat=True)

        try:
            dec = p.analyses.Decompiler(func, cfg=cfg)
        except:
            continue

        # convert function blocks to AIL blocks
        clinic = p.analyses.Clinic(func)

        # recover regions
        ri = p.analyses.RegionIdentifier(func, graph=clinic.graph)

        # structure it
        rs = p.analyses.RecursiveStructurer(ri.region)

        # simplify it
        s = p.analyses.RegionSimplifier(rs.result)

        codegen = p.analyses.StructuredCodeGenerator(func, s.result, cfg=cfg)

        the_kb = dec.clinic.variable_kb
        variable_manager = the_kb.variables[func.addr]
        var = variable_manager.get_variables()
        print(var)
        for v in var:
            if isinstance(v, SimRegisterVariable):
                print(v, v.reg)

        print()

        for v in var:
            if isinstance(v, SimStackVariable):
                print(v, v.addr)

        print(init_state.solver.eval(stack_base_addr))


if __name__ == "__main__":
    main(sys.argv)
