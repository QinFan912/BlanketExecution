import ctypes
import os
import sys
import pprint
from collections import defaultdict
import angr
from angr.analyses.decompiler.structured_codegen import CConstant, CExpression, CFunction, CDirtyExpression, CVariable, \
    CBinaryOp, CStatements, CUnsupportedStatement, CIfElse
from angr.sim_variable import SimRegisterVariable, SimStackVariable


def main(argv):
    base_addr = 0x4000000

    file_name = "rm"
    # file_path = "/home/qinfan/coreutils/coreutils-ARM32/src/" + file_name            # X86
    file_path = "/home/qinfan/coreutils/coreutils-X86-O2/src/" + file_name            # X86
    # file_path = "/home/qinfan/coreutils/coreutils-MIPS32/src/" + file_name            # X86

    p = angr.Project(file_path, auto_load_libs=False,
                     load_options={
                         'main_opts': {
                             'base_addr': base_addr
                         }
                     })

    cfg = p.analyses.CFG(show_progressbar=True, data_references=True, normalize=True)
    mem_data = cfg.memory_data
    # cfg = p.analyses.CFG()

    cc = p.analyses.CompleteCallingConventions(recover_variables=True)
    gvar = p.kb.variables['global']._variables
    print("gvar:", gvar)
    gvar_dict = defaultdict(list)

    kb = angr.KnowledgeBase(p)
    func = list(cfg.kb.functions.values())
    for i in func:
        print(i.name)
    function_numbers = len(func)
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

        dec = p.analyses.Decompiler(func, cfg=cfg)

        # # convert function blocks to AIL blocks
        # clinic = p.analyses.Clinic(func)
        #
        # # recover regions
        # ri = p.analyses.RegionIdentifier(func, graph=clinic.graph)
        #
        # # structure it
        # rs = p.analyses.RecursiveStructurer(ri.region)
        #
        # # simplify it
        # s = p.analyses.RegionSimplifier(rs.result)

        codegen = dec.codegen
        # codegen = p.analyses.StructuredCodeGenerator(func, s.result, cfg=cfg)

        print(codegen.text)

        print(codegen.posmap)
        for k, v in codegen.posmap.items():
            print(k, v)

        # if dec.codegen is None:
        #     continue
        the_kb = dec.clinic.variable_kb
        variable_manager = the_kb.variables[func.addr]
        var = variable_manager.get_variables()
        var_dict = defaultdict(list)

        l = list()
        for k, v in codegen.posmap.items():
            if isinstance(v.obj, CConstant):
                print(v.obj.value)
                print(v.obj.reference_values)
                if v.obj.reference_values:
                    x = v.obj.reference_values
                    for i, j in x.items():
                        print(i)
                        print(type(j))
                        if not isinstance(j, int):
                            y = j.content.decode()
                            print(y)
                            var_dict['string'].append(y)

                if isinstance(v.obj.value, int):
                    print(v.obj.value)
                    l.append(v.obj.value)
        l1 = sorted(list(set(l)))
        print(l1)
        var_dict['constant'] = l1
        print(var_dict)


if __name__ == "__main__":
    main(sys.argv)
    # print(ctypes.c_uint32(-130).value)
    # print(ctypes.c_uint32(-65608).value)        # 4294901688        FFFFFFB8
    # print(ctypes.c_uint32(-65656).value)        # 4294901640        FFFFFF88
    # print(ctypes.c_uint32(-65688).value)        # 4294901608        FFFFFF68
