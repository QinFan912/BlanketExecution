import angr
import sys
import claripy


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/05_angr_symbolic_memory")

    start_address = 0x08048601
    init_state = p.factory.blank_state(addr=start_address)

    # pass1 = claripy.BVS("pass1", 64)
    # pass2 = claripy.BVS("pass2", 64)
    # pass3 = claripy.BVS("pass3", 64)
    # pass4 = claripy.BVS("pass4", 64)
    pass1 = init_state.solver.BVS("pass1", 64)      # 设置四个符号变量
    pass2 = init_state.solver.BVS("pass2", 64)
    pass3 = init_state.solver.BVS("pass3", 64)
    pass4 = init_state.solver.BVS("pass4", 64)

    pass1_address = 0x0A1BA1C0          # 要输入的值的内存地址
    pass2_address = 0x0A1BA1C8
    pass3_address = 0x0A1BA1D0
    pass4_address = 0x0A1BA1D8

    init_state.memory.store(pass1_address, pass1)       # 将符号变量写入内存
    init_state.memory.store(pass2_address, pass2)
    init_state.memory.store(pass3_address, pass3)
    init_state.memory.store(pass4_address, pass4)

    sm = p.factory.simulation_manager(init_state)

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        password1 = found_state.solver.eval(pass1, cast_to=bytes).decode("utf-8")       # 状态求解,输出为字符串
        password2 = found_state.solver.eval(pass2, cast_to=bytes).decode("utf-8")
        password3 = found_state.solver.eval(pass3, cast_to=bytes).decode("utf-8")
        password4 = found_state.solver.eval(pass4, cast_to=bytes).decode("utf-8")

        print("Solution: {} {} {} {}".format(password1, password2, password3, password4))
    else:
        raise Exception("Solution not found")


if __name__ == "__main__":
    main(sys.argv)
