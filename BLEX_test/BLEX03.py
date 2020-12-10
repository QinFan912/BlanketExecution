import angr
import sys
import claripy


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/04_angr_symbolic_stack")

    function_start_address = 0x08048591

    args1 = claripy.BVS("args1", 32)
    args2 = claripy.BVS("args2", 32)

    init_state = p.factory.call_state(function_start_address, args1, args2)
    init_state.add_options = {angr.options.UNDER_CONSTRAINED_SYMEXEC}

    padding_size = 8

    init_state.regs.ebp = init_state.regs.esp       # 初始化ebp,设置栈的开始位置

    init_state.regs.esp -= padding_size     # 设置两个密码的栈空间

    init_state.stack_push(args1)
    init_state.stack_push(args2)

    sm = p.factory.simgr(init_state)
    sm.explore(find=0x08048678)

    if sm.found:
        found_state = sm.found[0]
        print(init_state.solver.eval(args1)), print(init_state.solver.eval(args2))
        print(found_state)
        print("yes")
    else:
        print("no")


if __name__ == "__main__":
    main(sys.argv)
