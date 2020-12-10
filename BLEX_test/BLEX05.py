from collections import defaultdict

import angr
import sys


def main(argv):
    base_addr = 0x4000000
    p = angr.Project("/home/qinfan/Ccode/test/test", auto_load_libs=False,
                     load_options={
                        'main_opts': {
                            'base_addr': base_addr
                        }
                     })

    with open('/home/qinfan/PycharmProjects/angr_test/BLEX_test/function11.txt', 'r') as f:
        function = f.readlines()
    func = list(function)
    print(func)
    max_function_number = len(func)

    function_start_address = base_addr + 0xa31
    function_end_address = base_addr + 0xac8
    # 0 0x76a 0x7d0
    # 1 0x7d1 0x868
    # 2 0x869 0x900
    # 3 0x901 0x998
    # 4 0x999 0xa30
    # 5 0xa31 0xac8
    # 6 0xac9 0xe60
    # 7 0xe61 0xf32

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

    sm = p.factory.simgr(init_state, save_unsat=True)

    while sm.active:
        # sm.step()
        # print(sm.active)
        for states in sm.active:
            states_addr = hex(states.addr)
            block_dict[states_addr] += 1
            print(block_dict)
            print(sm.active)

        for states in sm.active:
            states_addr = hex(states.addr)
            if block_dict[states_addr] >2:
                sm.active.remove(states)
                print(sm.active)

        sm.step()
        print("unsat:", sm.unsat)

        for state in sm.unsat:
            print(state.solver.constraints)
            state.solver.constraints.clear()
            print("clear 后:", state.solver.constraints)

        print("unsat:", sm.unsat)

        print("-----------", sm)
        sm.move(from_stash='unsat', to_stash='active')

        print("============", sm)
        print(sm.active)

        for states in sm.active:
            if states.history.jumpkind == "Ijk_Call":
                print("------------call==================")

        if len(sm.active) >= 5:
            del sm.active[5:]

    print("final_dict:", block_dict)

    block_cover = 0
    no_block_list = []
    for dic in block_list:
        if block_dict[dic] >= 1:
            block_cover += 1
        else:
            no_block_list.append(dic)
    print(no_block_list)

    coverage_rate = block_cover / block_nums
    print(coverage_rate)


if __name__ == "__main__":
    main(sys.argv)
