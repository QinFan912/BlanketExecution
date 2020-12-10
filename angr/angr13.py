import angr
import sys


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/13_angr_static_binary")

    init_state = p.factory.entry_state()

    printf_addr = 0x0804ED40
    scanf_addr = 0x0804ED80
    strcmp_addr = 0x08048280
    puts_addr = 0x0804F350
    libc_start_main_addr = 0x08048D10

    p.hook(printf_addr, angr.SIM_PROCEDURES['libc']['printf']())
    p.hook(scanf_addr, angr.SIM_PROCEDURES['libc']['scanf']())
    p.hook(strcmp_addr, angr.SIM_PROCEDURES['libc']['strcmp']())
    p.hook(puts_addr, angr.SIM_PROCEDURES['libc']['puts']())
    # 此外，请注意，执行二进制文件时，main函数不是被调用的第一段代码。在_start函数中，将调用__libc_start_main来启动程序。
    # 在Angr中，此函数中进行的初始化可能需要很长时间，因此应将其替换为SimProcedure
    # angr.SIM_PROCEDURES['glibc']['__libc_start_main']
    p.hook(libc_start_main_addr, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

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
