import sys
import pprint
from collections import defaultdict

from variable_recover.address_extractor import VariablesAddressExtractor

import angr
from angr.sim_variable import SimRegisterVariable, SimStackVariable


def main(argv):
    base_addr = 0x4000000

    file_path = "/home/qinfan/coreutils/coreutils-8.32/src/basename"
    save_path = '../X86-var-texts/basenaem_g01.txt'
    with open(file_path, 'rb') as f:
        extractor = VariablesAddressExtractor(f, save_path)
        extractor.parse_address()
    variables_offset = extractor.variables_offset
    func_names = extractor.func_names
    print(variables_offset)
    print(len(func_names))

    p = angr.Project(file_path, auto_load_libs=False,
                     load_options={
                         'main_opts': {
                             'base_addr': base_addr
                         }
                     })

    cfg = p.analyses.CFG()

    cc = p.analyses.CompleteCallingConventions(recover_variables=True)
    gvar = p.kb.variables['global']._variables
    print(gvar)
    gvar_dict = defaultdict(list)

    kb = angr.KnowledgeBase(p)
    func = list(cfg.kb.functions.values())
    # print(func)
    function_numbers = len(func)
    print(function_numbers)

    count = 0
    sp = 0
    normal_func = []
    similar_func = []
    for func in cfg.kb.functions.values():
        if func.is_simprocedure or func.is_plt:
            sp += 1
            # skil all SimProcedures and PLT stubs
            continue
        normal_func.append(func.name)
        print("##" * 50)
        print(func.name)
        if func.name in func_names:
            count += 1
            similar_func.append(func.name)
            print(func.name)
    print(count)
    print(similar_func)
    print(len(similar_func))
    print(func_names)

    align_func = []
    for func in cfg.kb.functions.values():
        if func.alignment:
            align_func.append(func.name)

    print(normal_func)
    print(len(normal_func))
    print(sp)
    print(function_numbers - sp)

    diff_func = []
    for func in normal_func:
        if func not in func_names:
            diff_func.append(func)

    print("$$ $"*50)
    print(align_func)
    print(len(align_func))
    print(diff_func)
    print(len(diff_func))

    ret = [i for i in diff_func if i not in align_func]
    print(ret)
    print(len(ret))


if __name__ == "__main__":
    main(sys.argv)
