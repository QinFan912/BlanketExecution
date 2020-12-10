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

    # 读取函数的开始和结束地址
    with open('/home/qinfan/PycharmProjects/angr_test/BLEX_test/function11.txt', 'r') as f:
        function = f.readlines()
    func = list(function)
    print(func)
    max = len(func)
    print("function_num: ",max/2)

    i = 0
    # 循环执行每个函数
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
        # 获取每个函数的基本块,加入字典
        while next_addr <= function_end_address:
            block = p.factory.block(next_addr)
            block_addr = hex(block.addr)
            print(block_addr)
            # 每个基本块以其开始地址为key进行计数
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
            print(sm.active)
            # 若state的开始地址与基本块开始地址相等,说明该基本块会被step,计数加一
            for states in sm.active:
                states_addr = hex(init_state.solver.eval(states.regs.ip))
                if states_addr in dict.keys():
                    dict[states_addr] += 1
                    print(dict)

            # 如果基本块已经被执行超过两次,就移除该基本块对应的state
            for states in sm.active:
                states_addr = hex(init_state.solver.eval(states.regs.ip))
                if states_addr in dict.keys():
                    if dict[states_addr] > 2:
                        sm.active.remove(states)
                        print(sm.active)

            # step执行
            sm.step()
            print(sm)

            # 如果进行函数调用,不进入执行调用函数,直接改变state的ip指向调用函数的结束地址
            for states in sm.active:
                if states.history.jumpkind == "Ijk_Call":
                    print("call")
                    # 被调用函数地址在函数列表中的获取
                    list_func = str(int(init_state.solver.eval(states.regs.ip) - base_addr)) + '\n'
                    print(list_func)
                    if list_func in func:
                        # 调用函数在函数列表中的index
                        index = func.index(list_func) + 2
                        states.regs.ip = base_addr +  int(func[index]) - 1
                        print(states.regs.ip)

            # 如果active中的state个数大于5个,删除后面过多的state
            if len(sm.active) >= 5:
                del sm.active[5:]

        print("final_dict:", dict)


if __name__ == "__main__":
    main(sys.argv)
