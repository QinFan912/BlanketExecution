import angr
import sys
import claripy


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/03_angr_symbolic_registers")    # 载入二进制文件,创建一个angr工程

    start_addr = 0x8048980     # 符号执行开始地址
    init_state = p.factory.blank_state(addr=start_addr)      # 用blank_state来实现从某个地址处载入

    pass1 = claripy.BVS("pass1", 32)        # 创建符号变量
    pass2 = claripy.BVS("pass2", 32)
    pass3 = claripy.BVS("pass3", 32)

    init_state.regs.eax = pass1         # 将符号变量给相应的寄存器
    init_state.regs.ebx = pass2
    init_state.regs.edx = pass3

    sm = p.factory.simulation_manager(init_state)       # 创建模拟器进行符号执行

    def is_good(state):         # 执行成功的状态
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):          # 执行失败的状态
        return b'Try again' in state.posix.dumps(1)     # 该状态执行路径的输出有'Try again'

    sm.explore(find=is_good, avoid=is_bad)      # 使用sm.explore进行模拟执行,find是想要执行分支，avoid是不希望执行的分支

    if sm.found:            # sm.found用于存储我们想要的状态
        found_state = sm.found[0]       # explore方法在找到到达目标地址的单个状态后停止

        password1 = found_state.solver.eval(pass1)      # found_state.found[0].solver用于存储状态的解，而eval函数则输入参数的值
        password2 = found_state.solver.eval(pass2)
        password3 = found_state.solver.eval(pass3)
        print("Solution:{:x} {:x} {:x}".format(password1, password2, password3))
    else:
        raise Exception("No solution found")


if __name__ == "__main__":
    main(sys.argv)
