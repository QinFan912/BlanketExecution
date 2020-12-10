import angr
import sys
import claripy


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/05_angr_symbolic_memory")

    function_start_address = 0x08048549
    # complex_function      0x08048549  0x080485A7
    # main                  0x080485A8  0x08048686
    # frame_dummy           0x08048500  0x08048526
    # print_msg             0x0804852B  0x08048548
    # register_tm_clones    0x080484A0  0x080484D3
    # deregister_tm_clones  0x08048470  0x08048499

    args1 = claripy.BVS("args1", 32)
    args2 = claripy.BVS("args2", 32)

    init_state = p.factory.call_state(function_start_address, args1, args2,
                                      add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC})

    padding_size = 8

    init_state.regs.ebp = init_state.regs.esp

    init_state.regs.esp -= padding_size

    init_state.stack_push(args1)
    init_state.stack_push(args2)

    sm = p.factory.simgr(init_state)
    sm.explore(find=0x080485A7)

    if sm.found:
        found_state = sm.found[0]
        print(found_state.solver.eval(args1), found_state.solver.eval(args2))
        print(found_state)
        print(sm)
        print("yes")
    else:
        print("no")


if __name__ == "__main__":
    main(sys.argv)
