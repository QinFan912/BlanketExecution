import angr
import sys
import claripy


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/06_angr_symbolic_dynamic_memory")

    start_address = 0x08048699
    init_state = p.factory.blank_state(addr=start_address)

    # 任意开辟的新空间地址
    fake_addr0 = 0x66666666
    fake_addr1 = 0x66666686

    # 原来的指向数据的指针的地址
    buff0_addr = 0x0ABCC8A4
    buff1_addr = 0x0ABCC8AC

    # 原指向数据的指针指向新开辟空间的地址
    init_state.memory.store(buff0_addr, fake_addr0, endness=p.arch.memory_endness)
    init_state.memory.store(buff1_addr, fake_addr1, endness=p.arch.memory_endness)

    pass0 = init_state.solver.BVS("pass0", 64)      # 设置两个符号变量
    pass1 = init_state.solver.BVS("pass1", 64)

    # 将符号变量写入新开辟空间
    init_state.memory.store(fake_addr0, pass0)
    init_state.memory.store(fake_addr1, pass1)

    sm = p.factory.simulation_manager(init_state)

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        password0 = found_state.solver.eval(pass0, cast_to=bytes).decode("utf-8")       # 状态求解,输出为字符串
        password1 = found_state.solver.eval(pass1, cast_to=bytes).decode("utf-8")
        print("Solution: {} {}".format(password0, password1))
    else:
        raise Exception("Solution not found")


if __name__ == "__main__":
    main(sys.argv)
