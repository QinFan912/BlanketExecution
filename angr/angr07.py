import angr
import sys


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/07_angr_symbolic_file")

    start_sddr = 0x080488D6         # 开始地址,需要在读取文件之前
    init_state = p.factory.blank_state(addr=start_sddr)

    file_name = "OJKSQYDP.txt"      # 文件名
    file_size = 0x64        # 文件大小

    password = init_state.solver.BVS("password", file_size*8)       # 生成符号变量

    # 将符号变量放入文件
    password_file = angr.storage.SimFile(file_name, content=password, size=file_size)
    init_state.fs.insert(file_name, password_file)

    sm = p.factory.simgr(init_state)

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        password_str = found_state.solver.eval(password, cast_to=bytes).decode("utf-8")
        print("Solution: ", password_str)
    else:
        raise Exception("Solution not found")


if __name__ == "__main__":
    main(sys.argv)
