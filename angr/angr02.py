import angr
import sys


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/02_angr_find_condition")

    # bin_path = argv[1]
    # p = angr.Project(bin_path)

    init_state = p.factory.entry_state()
    sm = p.factory.simulation_manager(init_state)

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        print(found_state.posix.dumps(0))
        # print("Solution:", found_state)


if __name__ == "__main__":
    main(sys.argv)
