from collections import defaultdict

import angr
import sys


def main(argv):
    base_addr = 0x4000000
    p = angr.Project("/home/qinfan/coreutils/coreutils-8.32/src/chown", auto_load_libs=False,
                     load_options={
                        'main_opts': {
                            'base_addr': base_addr
                        }
                     })

    # with open('/home/qinfan/PycharmProjects/angr_test/BLEX_test/function.txt', 'r') as f:
    #     function = f.readlines()
    # func = list(function)
    # print(func)
    # max = len(func)
    # print(max/2)

    # function_start_address = 0x4003633
    function_start_address = base_addr + 29134
    function_end_address = base_addr + 30233 - 1

    next_addr = function_start_address
    block_nums = 0
    block_list = []
    block_dict = defaultdict(int)
    while next_addr <= function_end_address:
        block = p.factory.block(next_addr)
        block_addr = hex(block.addr)
        # print(block_addr)
        block_list.append(block_addr)
        block_nums += 1
        add_addr = block.size
        next_addr += add_addr
    print(block_nums)
    print(block_list)
    print(block_dict)

    init_state = p.factory.blank_state(addr=function_start_address,
                                       add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC,
                                                    angr.options.CALLLESS,
                                                    angr.options.LAZY_SOLVES})

    sm = p.factory.simgr(init_state, save_unsat=True, save_unconstrained=True)

    while sm.active:

        for state in sm.active:
            state_addr = hex(state.addr)
            block_dict[state_addr] += 1
            print(block_dict)
            print(sm.active)

        for state in sm.active[::-1]:
            state_addr = hex(state.addr)
            if block_dict[state_addr] > 5:
                sm.active.remove(state)
                print(sm.active)

        print("#"*50)
        sm.step()

        print(sm)
        print(sm.active)

        print("unsat:",sm.unsat)
        print("unconstrained:",sm.unconstrained)

        # for state in sm.unconstrained[::-1]:
        #     print(state)
        #     # state.regs.ip = state.stack_pop()
        #     print(state.regs.ip)
        #     if state.solver.eval(state.regs.ip) not in range(function_start_address, function_end_address):
        #         sm.unconstrained.remove(state)
        # sm.move(from_stash="unconstrained", to_stash="active")

        # print("unsat:", sm.unsat)

        for state in sm.unsat:
            # print(state.solver.constraints)
            state.solver.constraints.clear()
            # print("clear 后:", state.solver.constraints)

        print("-----------", sm)

        sm.move(from_stash='unsat', to_stash='active')

        print("============", sm)
        print(sm.active)

        # for state in sm.active:
        #     ss = p.factory.successors(state)
        #     unsat_succ = ss.unsat_successors
        #     print(unsat_succ)

    print("final_dict:", block_dict)

    block_cover = 0
    no_block_list = []
    for dic in block_list:
        if block_dict[dic] >= 1:
            block_cover += 1
        else:
            no_block_list.append(dic)
    print(no_block_list)

    coverage_rate = block_cover/block_nums
    print(coverage_rate)
    # write_line = [block_nums, block_cover, coverage_rate]
    # with open('/home/qinfan/PycharmProjects/angr_test/BLEX_test/coverage_rate.txt', 'a') as f:
    #     f.writelines(str(write_line)+'\n')


if __name__ == "__main__":
    main(sys.argv)
