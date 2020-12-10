import angr
import sys


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/08_angr_constraints")

    start_sddr = 0x08048625       # 开始地址
    init_state = p.factory.blank_state(addr=start_sddr)

    password = init_state.solver.BVS("password", 16*8)       # 生成符号变量
    password_addr = 0x0804A050
    init_state.memory.store(password_addr, password)        # 将符号变量存入相应地址

    sm = p.factory.simgr(init_state)

    check_addr = 0x08048565     # 要执行的比较函数的入口地址
    sm.explore(find=check_addr)

    if sm.found:
        check_state = sm.found[0]

        desire_string = "AUPDNNPROEZRJWKB"      # 用来与输入比较的字符串
        check_param1 = password_addr        # 需要比较的参数的地址
        check_param2 = 0x10             # 需要比较的参数的大小

        check_bvs = check_state.memory.load(check_param1, check_param2)    # 取出需要比较的参数的值

        check_constraint = desire_string == check_bvs       # 约束条件

        check_state.add_constraints(check_constraint)       # 添加约束条件

        solution = check_state.solver.eval(password, cast_to=bytes).decode("utf-8")
        print("Solution: ", solution)
    else:
        raise Exception("Solution not found")


if __name__ == "__main__":
    main(sys.argv)
