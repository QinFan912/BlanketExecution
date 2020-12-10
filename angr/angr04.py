import angr
import sys
import claripy


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/04_angr_symbolic_stack")          # 载入二进制文件

    start_addr = 0x08048697     # 符号执行开始地址
    init_state = p.factory.blank_state(addr=start_addr)     # 用blank_state来实现从某个地址处载入

    padding_size = 8        # 两个32位密码总共占8个字节

    init_state.regs.ebp = init_state.regs.esp       # 初始化ebp,设置栈的开始位置

    init_state.regs.esp -= padding_size     # 设置两个密码的栈空间

    pass1 = init_state.solver.BVS("pass1", 32)        # 创建符号变量
    pass2 = init_state.solver.BVS("pass2", 32)
    # pass1 = claripy.BVS("pass1", 32)
    # pass2 = claripy.BVS("pass2", 32)

    init_state.stack_push(pass1)        # 符号变量进栈
    init_state.stack_push(pass2)

    sm = p.factory.simgr(init_state)        # 创建模拟器进行符号执行

    def is_good(state):     # 执行成功的状态
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):      # 执行失败的状态
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)       # 使用sm.explore进行模拟执行

    if sm.found:
        found_state = sm.found[0]
        password1 = found_state.solver.eval(pass1)      # found_state.found[0].solver用于存储状态的解，而eval函数则输入参数的值
        password2 = found_state.solver.eval(pass2)
        print("Solution: {} {}".format(password1, password2))
    else:
        raise Exception("Solution not found")


if __name__ == "__main__":
    main(sys.argv)
