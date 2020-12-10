import angr
import sys
import claripy


def main(argv):
    base_addr = 0x4000000
    p = angr.Project("/home/qinfan/Ccode/test/cp", auto_load_libs=False,
                     load_options={
                        'main_opts': {
                            'base_addr': base_addr
                        }
                     })

    with open('/home/qinfan/PycharmProjects/angr_test/BLEX_test/function.txt', 'r') as f:
        function = f.readlines()
    func = list(function)
    print(func)
    max = len(func)
    print(max/2)

    i = 0
    while i < max-1:
        start_addr = int(func[i])
        end_addr = int(func[i + 1]) - 1
        i += 2

        function_start_address = base_addr + start_addr
        function_end_address = base_addr + end_addr

        next_addr = function_start_address
        block_nums = 0
        dict = {}
        counter = 0
        while next_addr <= function_end_address:
            block = p.factory.block(next_addr)
            block_addr = hex(block.addr)
            print(block_addr)
            dict[block_addr] = counter
            block_nums += 1
            add_addr = block.size
            next_addr += add_addr
        print("block_nums = ", block_nums)
        print(dict)

        init_state = p.factory.blank_state(addr=function_start_address,
                                           add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC})

        sm = p.factory.simgr(init_state)

        while sm.active:
            # sm.step()
            print(sm.active)
            for states in sm.active:
                states_addr = hex(init_state.solver.eval(states.regs.ip))
                if states_addr in dict.keys():
                    dict[states_addr] += 1
                    # print(dict)
                    # print(sm.active)

            for states in sm.active:
                states_addr = hex(init_state.solver.eval(states.regs.ip))
                if states_addr in dict.keys():
                    if dict[states_addr] > 2:
                        sm.active.remove(states)
                        # print(sm.active)

            sm.step()

            for states in sm.active:
                if states.history.jumpkind == "Ijk_Call":
                    # print("call")
                    list_func = str(int(init_state.solver.eval(states.regs.ip) - base_addr)) + '\n'
                    # print(list_func)
                    if list_func in func:
                        index = func.index(list_func) + 2
                        states.regs.ip = base_addr + int(func[index]) - 1
                        # print(states.regs.ip)

            if len(sm.active) >= 5:
                del sm.active[5:]

        print("final_dict:", dict)


if __name__ == "__main__":
    main(sys.argv)
