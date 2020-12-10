import angr
import claripy


def main():
    p = angr.Project("/home/qinfan/study/angr-doc-master/examples/ais3_crackme/ais3_crackme")
    argv1 = claripy.BVS("", 100*8)
    init_state = p.factory.entry_state(args=["", argv1])
    sm = p.factory.simulation_manager(init_state)
    sm.explore(find=0x400602)
    found = sm.found[0]
    solution = found.solver.eval(argv1, cast_to=bytes)
    return solution


if __name__ == "__main__":
    print(repr(main()))
