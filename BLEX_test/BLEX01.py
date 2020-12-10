import angr
import sys


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/04_angr_symbolic_stack",
                     auto_load_libs=False)

    function_start_address = 0x080486F4
    # complex_function0  0x080484A9   0x08048590
    # complex_function1  0x08048591   0x08048678
    # handle_user        0x08048679   0x080486F3
    # main               0x080486F4   0x08048726
    # frame_dummy        0x08048460   0x08048486  wrong
    # register_tm_clones 0x08048400   0x08048433
    # deregister_tm_clones 0x080483D0 0x080483F9
    # print_msg          0x0804848B   0x080484A8
    init_state = p.factory.blank_state(addr=function_start_address,
                                       add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC})

    sm = p.factory.simgr(init_state)
    function_end_address = 0x08048726
    sm.explore(find=function_end_address)

    if sm.found:
        found_state = sm.found[0]
        print(found_state)
        print(sm)
        print("Good Job")
    else:
        print("Try Again")


if __name__ == "__main__":
    main(sys.argv)
