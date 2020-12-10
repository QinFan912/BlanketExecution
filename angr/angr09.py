import angr
import sys
import claripy


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/09_angr_hooks")

    init_state = p.factory.entry_state()

    check_addr = 0x080486B3     # 需要hook的函数被调用的地址
    # angr.Hook中的length参数指定执行引擎在完成挂钩后应跳过多少字节。这将允许钩子替换某些指令（或指令组）。
    # 这将是跳过长度,call指令的长度
    check_skip_size = 5

    @p.hook(check_addr, length=check_skip_size)
    def check_hook(state):      # hook成这个函数
        user_input_addr = 0x0804A054    # 用户输入字符串地址
        user_input_length = 16          # 用户输入字符串长度

        user_input_string = state.memory.load(user_input_addr, user_input_length)    # 加载用户输入字符串

        desire_string = "XYMKBKUHNIQYNQXE"      # 被比较的字符串

        # 如果是整数，gcc使用eax来存储返回值。如果desire_string == user_input_string，我们需要将eax设置为1，否则设置为0
        state.regs.eax = claripy.If(                # 创建条件判断claripy.If()
            desire_string == user_input_string,     # 条件
            claripy.BVV(1, 32),                     # 条件为True时的返回值      创建一个数值claripy.BVV(值,值大小)
            claripy.BVV(0, 32)                      # 条件为False时的返回值
        )

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm = p.factory.simgr(init_state)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        print("Solution: ", found_state.posix.dumps(0))
    else:
        raise Exception("Solution not found")


if __name__ == "__main__":
    main(sys.argv)
