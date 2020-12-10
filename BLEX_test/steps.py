import sys
import pprint
from collections import defaultdict

import angr


def main(argv):
    base_addr = 0x4000000
    p = angr.Project("/home/qinfan/coreutils/coreutils-8.32/src/cp", auto_load_libs=False,
                     load_options={
                         'main_opts': {
                             'base_addr': base_addr
                         }
                     })

    # with open('/home/qinfan/PycharmProjects/angr_test/BLEX_test/function.txt', 'r') as f:
    #    function = f.readlines()
    cfg = p.analyses.CFG()
    func = list(cfg.kb.functions.values())
    # print(func)
    function_numbers = len(func)
    print(function_numbers)

    not_cover = 0
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

        function_start_address = start_addr
        function_end_address = end_addr - 1

        next_addr = function_start_address
        block_nums = 0
        block_list = []
        block_dict = defaultdict(int)

        while next_addr <= function_end_address:
            block = p.factory.block(next_addr)
            block_list.append(block.addr)
            block_nums += 1
            add_addr = block.size
            next_addr += add_addr
        # print(block_nums)
        # print(block_list)

        init_state = p.factory.blank_state(addr=function_start_address,
                                           add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC,
                                                        angr.options.CALLLESS,
                                                        angr.options.LAZY_SOLVES})

        sm = p.factory.simgr(init_state, save_unsat=True)

        while sm.active:

            # keep one state for each address
            all_actives = defaultdict(list)
            for state in sm.active:
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
                            # s.regs.ip = ent
                            sm.active.append(s)

            # print(sm.unsat)
            for state in sm.unsat:
                state.solver.constraints.clear()
            sm.move(from_stash='unsat', to_stash='active')

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

            write_line = [func.name, block_nums, block_cover, coverage_rate, list(map(hex, blocks_diff))]
            with open('/home/qinfan/PycharmProjects/angr_test/coverage_rate/cp.txt', 'a') as f:
                f.writelines(str(write_line)+'\n')
    print(not_cover)


if __name__ == "__main__":
    main(sys.argv)
