import sys
import pprint
from collections import defaultdict

import angr
from angr.sim_variable import SimRegisterVariable, SimMemoryVariable, SimStackVariable


def main(argv):
    base_addr = 0x4000000
    p = angr.Project("/home/qinfan/coreutils/coreutils-8.32/src/basename",
                     auto_load_libs=False,
                     load_options={
                         'main_opts': {
                             'base_addr': base_addr
                         }
                     })

    cfg = p.analyses.CFG()
    kb = angr.KnowledgeBase(p)
    cc = p.analyses.CompleteCallingConventions(recover_variables=True)
    gvar = p.kb.variables['global']._variables
    print(gvar)
    print(len(gvar))
    # for gv in gvar:
    #     print(gv.name,hex(gv.addr))

    func = list(cfg.kb.functions.values())
    print(func)
    print(func[0])
    function_numbers = len(func)
    print(function_numbers)

    for f in cfg.kb.functions.values():
        if f.name == 'main':
            vg = p.analyses.VariableRecoveryFast(func, kb=kb)
            var_manager = vg.variable_manager[f.addr]
            print(f.addr)
            var = var_manager.get_variables()
            print("var:", var)

            for v in var:
                if isinstance(v, SimStackVariable):
                    print(v.name, v.offset)

    # ccc = p.analyses.CompleteCallingConventions(recover_variables=True)


'''
    for func in cfg.kb.functions.values():
        if func.is_simprocedure or func.is_plt:
            # skil all SimProcedures and PLT stubs
            continue
        start_addr = func.addr
        end_addr = None
        for b in func.blocks:
            if end_addr is None or b.addr + b.size > end_addr:
                end_addr = b.addr + b.size
        if end_addr is None:
            continue

        vg = p.analyses.VariableRecoveryFast(func, kb=kb)
        var_manager = vg.variable_manager[func.addr]
        print(func.addr)
        var = var_manager.get_variables()
        print("var:", var)
'''

if __name__ == '__main__':
    main(sys.argv)
