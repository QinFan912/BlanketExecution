import angr
import sys
import claripy


def main(argv):
    # 共享库使用与位置无关的代码编译。将需要指定基本地址。
    # 共享库中的所有地址均为base + offset，其中offset为文件中的地址。
    base = 0x4000000
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/lib14_angr_shared_library.so",
                     load_options={
                         'auto_load_libs': False,
                         'main_opts': {
                             'custom_base_addr': base
                         }
                     })         # 加载动态链接库

    cfg = p.analyses.CFGFast()
    print("This is the graph:", cfg.graph)

    buffer_pointer = claripy.BVV(0x3000000, 32)     # 创建一个32位指针,值任意,是指向输入值的地址

    validate_function_addr = base + 0x6D7      # 函数开始地址
    # 起始状态包括要调用的库函数和它的参数
    init_state = p.factory.call_state(validate_function_addr, buffer_pointer, claripy.BVV(8, 32))

    password = claripy.BVS("password", 8*8)
    init_state.memory.store(buffer_pointer, password)

    sm = p.factory.simgr(init_state)

    success_addr = base + 0x783        # 函数结束地址
    sm.explore(find=success_addr)

    if sm.found:
        found_state = sm.found[0]
        # 确定输出存放位置,并确保为真
        found_state.add_constraints(found_state.regs.eax != 0)  # 添加的限制条件
        solution = found_state.solver.eval(password, cast_to=bytes).decode("utf-8")
        print("Solution: ", solution)
    else:
        raise Exception("Solution not found")


if __name__ == "__main__":
    main(sys.argv)
