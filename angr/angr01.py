import sys
import angr
import claripy


def main():
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/01_angr_avoid")
    argv1 = claripy.BVS("", 100 * 8)
    init_state = p.factory.entry_state(args=["", argv1])
    sm = p.factory.simulation_manager(init_state)
    sm.explore(find=0x80485E0, avoid=0x80485A)
    found = sm.found[0]
    solution = found.solver.eval(argv1, cast_to=bytes)
    return solution


if __name__ == "__main__":
    print(repr(main()))
    sys.argv