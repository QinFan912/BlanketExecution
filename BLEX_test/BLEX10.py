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

    with open('/home/qinfan/PycharmProjects/angr_test/function_addrs/chown.txt', 'r') as f:
        function = f.readlines()
    func = list(function)
    print(func)
    function_numbers = len(func)
    print(function_numbers/2)

    not_cover = 0
    i = 0
    while i < function_numbers-1:
        # 每个函数的开始和结束地址
        start_addr = int(func[i])
        end_addr = int(func[i + 1]) - 1
        i += 2

        function_start_address = base_addr + start_addr
        function_end_address = base_addr + end_addr - 1

        next_addr = function_start_address
        block_nums = 0
        block_list = []
        block_dict = defaultdict(int)
        # 计算函数的block个数及地址列表
        while next_addr <= function_end_address:
            block = p.factory.block(next_addr)
            block_addr = hex(block.addr)
            block_list.append(block_addr)
            block_nums += 1
            add_addr = block.size
            next_addr += add_addr
        print(block_nums)
        print(block_list)

        init_state = p.factory.blank_state(addr=function_start_address,
                                           add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC,
                                                        angr.options.CALLLESS,
                                                        angr.options.LAZY_SOLVES})

        sm = p.factory.simgr(init_state, save_unsat=True, save_unconstrained=True)

        while sm.active:
            # 每个要被执行的block计数加一
            for state in sm.active:
                state_addr = hex(state.addr)
                block_dict[state_addr] += 1
                # print(block_dict)
                # print(sm.active)

            # 当block被执行超过一定次数后,移除该state
            for state in sm.active[::-1]:
                state_addr = hex(state.addr)
                if block_dict[state_addr] > 5:
                    sm.active.remove(state)

            print(sm.active)
            # step()
            sm.step()
            print(sm.unsat)
            print(sm.unconstrained)
            # 移除unconstrained中地址不在该函数中的state
            for state in sm.unconstrained[::-1]:
                # print(state)
                # print(state.regs.ip)
                if state.solver.eval(state.regs.ip) not in range(function_start_address, function_end_address):
                    sm.unconstrained.remove(state)
            # 将unconstrained中的state移到active中
            sm.move(from_stash='unconstrained', to_stash='active')
            # 清除unsat中的state的限制条件
            for state in sm.unsat:
                state.solver.constraints.clear()
            # 将unsat中的state移到active中
            sm.move(from_stash='unsat', to_stash='active')

        print("final_dict:", block_dict)
        # 计算被执行的block个数
        block_cover = 0
        for dic in block_list:
            if block_dict[dic] >= 1:
                block_cover += 1

        coverage_rate = block_cover / block_nums

        # 未被完全执行的block
        if coverage_rate < 1:
            not_cover += 1

        write_line = [block_nums, block_cover, coverage_rate]
        with open('/home/qinfan/PycharmProjects/angr_test/function_addrs/coverage_chown.txt', 'a') as f:
            f.writelines(str(write_line)+'\n')
    print(not_cover)


if __name__ == "__main__":
    main(sys.argv)
