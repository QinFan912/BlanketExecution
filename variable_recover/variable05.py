import os
import sys
import pprint
from collections import defaultdict

from variable_recover.address_extractor import VariablesAddressExtractor

import angr
from angr.sim_variable import SimRegisterVariable, SimStackVariable


def main(argv):
    base_addr = 0x4000000

    file_name = "rm"
    # file_path = "/home/qinfan/coreutils/coreutils-8.32/src/" + file_name            # X86
    file_path = "/home/qinfan/coreutils/coreutils-8(1).32/src/" + file_name  # ARM
    # file_path = '/home/qinfan/Ccode/test/arm_variables'
    # file_path = '../variable_recover/global01'

    # X86 save_path:
    # X86_path = '/home/qinfan/PycharmProjects/angr_test/var_texts/' + file_name + "_quchong.txt"
    # if os.path.exists(X86_path):
    #     print('{} already exists, removed!'.format(X86_path))
    #     os.remove(X86_path)

    # arm save_path:
    arm_path = '/home/qinfan/PycharmProjects/angr_test/ARM_Var_tests/' + file_name + ".txt"
    if os.path.exists(arm_path):
        print('{} already exists, removed!'.format(arm_path))
        os.remove(arm_path)

    '''
    save_path = '../var_texts/VarDwarf.txt'
    with open(file_path, 'rb') as f:
        extractor = VariablesAddressExtractor(f, save_path)
        extractor.parse_address()
    variables_offset = extractor.variables_offset
    print("variables_offset:", variables_offset)
    '''

    p = angr.Project(file_path, auto_load_libs=False,
                     load_options={
                         'main_opts': {
                             'base_addr': base_addr
                         }
                     })

    min_addr = p.loader.min_addr

    cfg = p.analyses.CFG(show_progressbar=True, data_references=True)
    mem_data = cfg.memory_data
    # cfg = p.analyses.CFG()

    cc = p.analyses.CompleteCallingConventions(recover_variables=True)
    gvar = p.kb.variables['global']._variables
    print("gvar:", gvar)
    gvar_dict = defaultdict(list)

    kb = angr.KnowledgeBase(p)
    func = list(cfg.kb.functions.values())
    # print(func)
    function_numbers = len(func)
    print("function_numbers:", function_numbers)

    not_cover = 0
    for func in cfg.kb.functions.values():
        if func.is_simprocedure or func.is_plt:
            # skil all SimProcedures and PLT stubs
            continue
        if func.alignment:
            # skil all aligement functions
            continue

        start_addr = func.addr
        # end_addr = None
        # for b in func.blocks:
        #     if end_addr is None or b.addr + b.size > end_addr:
        #         end_addr = b.addr + b.size
        # if end_addr is None:
        #     continue
        #
        # function_start_address = start_addr

        block_nums = 0
        block_list = []
        block_dict = defaultdict(int)

        v = p.analyses.VariableRecoveryFast(func, kb=kb)
        print(v)
        var_manager = v.variable_manager[func.addr]
        print(var_manager)
        var = var_manager.get_variables()
        print(var)
        print(len(var))

        for b in func.blocks:
            block_list.append(b.addr)
            block_nums += 1
        # print(block_nums)
        # print(block_list)

        init_state = p.factory.blank_state(addr=start_addr, mode="fastpath",
                                           add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC,
                                                        angr.options.CALLLESS,
                                                        angr.options.LAZY_SOLVES})

        stack_base_addr = init_state.regs.sp
        print("stack_base_addr:", stack_base_addr)

        sm = p.factory.simgr(init_state, save_unsat=True)

        var_dict = defaultdict(list)

        def track_register(state):
            if state.inspect.reg_write_offset == state.arch.ip_offset:
                return
            print("state %s is about to do a register write" % state)
            print("write address:", state.solver.eval(state.inspect.reg_write_offset))
            if state.inspect.reg_write_expr.symbolic:
                print("Expr is symbolic. skip.")
                return
            print("expr:", state.solver.eval(state.inspect.reg_write_expr))
            expr = state.solver.eval(state.inspect.reg_write_expr)
            for va in var:
                if isinstance(va, SimRegisterVariable):
                    if state.solver.eval(state.inspect.reg_write_offset) == va.reg:
                        if expr in mem_data:
                            d = state.mem[expr].deref.int.concrete
                            var_dict[va.name].append(d)
                        else:
                            var_dict[va.name].append(expr)
                        # var_dict[va.name] = list(set(var_dict[va.name]))

                    old_list = var_dict[va.name]
                    for x in old_list[::-1]:
                        if x >= min_addr:
                            obj = p.loader.find_object_containing(addr=x)
                            if obj:
                                sec = obj.find_section_containing(addr=x)
                                if sec:
                                    d = state.mem[sec.vaddr].deref.int.concrete
                                    i = old_list.index(x)
                                    old_list[i] = d
                                else:
                                    old_list.remove(x)
                            else:
                                old_list.remove(x)

                    new_list = sorted(list(set(old_list)))
                    var_dict[va.name] = new_list

        def track_stack(state):
            print("state %s is about to do a memory write" % state)
            print("The address of the state:", hex(state.addr))
            print("the SP of the state:", state.regs.sp)
            print("write address:", state.inspect.mem_write_address)
            print("expr:", state.inspect.mem_write_expr)  # state.solver.eval(state.inspect.mem_write_expr))
            if state.inspect.mem_write_expr.symbolic:
                print("Expr is symbolic. skip.")
                return

            expr = state.solver.eval(state.inspect.mem_write_expr)
            for va in var:
                if isinstance(va, SimStackVariable):
                    # # 通过dwarf信息恢复变量名
                    # for k, v in variables_offset.items():
                    #     if k == func.name:
                    #         for i in range(len(v)):
                    #             if va.addr == v[i][1]:
                    #                 va.name = v[i][0]
                    #                 print(va.name)
                    if state.solver.eval(state.regs.sp) - state.solver.eval(stack_base_addr) == va.addr:
                        if expr in mem_data:
                            d = state.mem[expr].deref.int.concrete
                            var_dict[va.name].append(d)
                        else:
                            var_dict[va.name].append(expr)
                        # var_dict[va.name].append(state.solver.eval(state.inspect.mem_write_expr))
                        old_list = var_dict[va.name]
                        for x in old_list[::-1]:
                            if x >= min_addr:
                                obj = p.loader.find_object_containing(addr=x)
                                if obj:
                                    sec = obj.find_section_containing(addr=x)
                                    if sec:
                                        d = state.mem[sec.vaddr].deref.int.concrete
                                        i = old_list.index(x)
                                        old_list[i] = d
                                    else:
                                        old_list.remove(x)
                                else:
                                    old_list.remove(x)

                        new_list = sorted(list(set(old_list)))
                        var_dict[va.name] = new_list

        def track_mem(state):
            print("state %s is about to do a memory write" % state)
            print("The address of the state:", hex(state.addr))
            print("write address:", state.inspect.mem_write_address)
            print("expr:", state.solver.eval(state.inspect.mem_write_expr))
            for gv in gvar:
                if state.solver.symbolic(state.inspect.mem_write_address):
                    continue
                if state.solver.eval(state.inspect.mem_write_address) == gv.addr:
                    gvar_dict[gv.name].append(state.solver.eval(state.inspect.mem_write_expr))

        init_state.inspect.b("reg_write", when=angr.BP_AFTER, action=track_register)
        init_state.inspect.b("mem_write", when=angr.BP_AFTER, action=track_stack)

        if gvar:
            init_state.inspect.b("mem_write", when=angr.BP_AFTER, action=track_mem)

        while sm.active:

            # keep one state for each address
            all_actives = defaultdict(list)
            for state in sm.active:
                if state.regs.ip.symbolic:
                    continue
                all_actives[state.addr].append(state)
            sm.stashes['active'] = [next(iter(v)) for v in all_actives.values()]

            print(all_actives)
            print(sm.active)

            last_step_addrs = []
            for state in sm.active:
                block_dict[state.addr] += 1
                last_step_addrs.append(state.addr)
                # print(block_dict)
                # print(sm.active)

            for state in sm.active[::-1]:
                if block_dict[state.addr] > 2:
                    sm.active.remove(state)

            print(sm.active)
            print("#" * 100)
            for s in sm.active:
                if s.addr == 0:
                    continue
                b = p.factory.block(s.addr)
                print(b)
            sm.step()
            print(sm.active)

            # process indirect jumps that are potentially jump tables
            for state_addr in last_step_addrs:
                if state_addr in cfg.jump_tables:
                    # load all targets
                    jt = cfg.jump_tables[state_addr]
                    entries = set(jt.jumptable_entries)
                    # create a successor for each entry
                    if sm.active + sm.unsat:
                        template_state = next(iter(sm.active + sm.unsat))
                        for ent in entries:
                            print("[.] Creating an active state for jump table entry %#x." % ent)
                            s = template_state.copy()
                            s.regs._ip = ent
                            sm.active.append(s)

            # print(sm.unsat)
            for state in sm.unsat:
                state.solver.constraints.clear()
            sm.move(from_stash='unsat', to_stash='active')

        value_set = set()
        result = dict()
        for k, v in var_dict.items():
            if str(v) not in value_set:
                value_set.add(str(v))
                result[k] = v
            else:
                var_dict[k] = None

        # X86变量取值信息:
        # with open(X86_path, 'a') as f:
        #     f.writelines(func.name + ":" + '\n' + str(result) + '\n')

        # ARM变量取值信息:
        with open(arm_path, 'a') as f:
            f.writelines(func.name + ":" + '\n' + str(result) + '\n')

        # print("final_dict:", block_dict)
        block_cover = 0
        for dic in block_list:
            if dic in block_dict and block_dict[dic] >= 1:
                block_cover += 1

        coverage_rate = block_cover / block_nums

        if coverage_rate < 1:
            blocks_diff = set(block_list).difference(set(block_dict))
            print("### Function %s" % func.name)
            print("### The following blocks are not covered:")
            pprint.pprint(list(map(hex, blocks_diff)))
            print("###")
            not_cover += 1

    print("!!" * 50)
    print(gvar)
    print(gvar_dict)
    # 记录X86里面的全局变量
    # if gvar_dict:
    #     with open(X86_path, 'a') as f:
    #         f.writelines('\n' + "Global Variables:" + '\n' + str(gvar_dict) + '\n')
    print("!!" * 50)

    # 记录没有遍历的基本块
    # write_line = [func.name, block_nums, block_cover, coverage_rate, list(map(hex, blocks_diff))]
    # with open('/home/qinfan/PycharmProjects/angr_test/coverage_rate/cp.txt', 'a') as f:
    #     f.writelines(str(write_line)+'\n')
    print(not_cover)


if __name__ == "__main__":
    main(sys.argv)
