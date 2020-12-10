import angr
import sys
import claripy


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/10_angr_simprocedures")

    init_state = p.factory.entry_state()

    # 定义一个继承angr.SimProcedure的类，以利用Angr的SimProcedures
    class mySimPro(angr.SimProcedure):
        def run(self, user_input_addr, user_input_length):      # user_input_addr,user_input_length表示被hook的函数的两个参数
            user_input_string = self.state.memory.load(         # load输入的字符串
                user_input_addr,
                user_input_length
            )
            desire_string = "ORSDDWXHZURJRBDH"      # 被比较的字符串

            return claripy.If(
                user_input_string == desire_string,
                claripy.BVV(1, 32),
                claripy.BVV(0, 32)
            )

    check_symbol = "check_equals_ORSDDWXHZURJRBDH"      # 要hook的函数名字
    p.hook_symbol(check_symbol, mySimPro())             # 通过函数名hook函数

    sm = p.factory.simgr(init_state)

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        print("Solution: ", found_state.posix.dumps(0))
    else:
        raise Exception("Solution not found")


if __name__ == "__main__":
    main(sys.argv)
