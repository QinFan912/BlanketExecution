import angr
import sys


def main(argv):
    base_addr = 0x4000000
    p = angr.Project("/home/qinfan/Ccode/test", auto_load_libs=False,
                     load_options={
                        'main_opts': {
                            'custom_base_addr': base_addr
                        }
                     })

    function_start_address = base_addr + 0xac9
    # 0 0x76a 0x7d0
    # 1 0x7d1 0x868
    # 2 0x869 0x900
    # 3 0x901 0x998
    # 4 0x999 0xa30
    # 5 0xa31 0xac8
    # 6 0xac9 0xe60
    # 7 0xe61 0xf32

    init_state = p.factory.blank_state(addr=function_start_address,
                                       add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC})

    sm = p.factory.simgr(init_state)
    cfg = p.analyses.CFGFast()
    sm.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=5))
    sm.use_technique(angr.exploration_techniques.LengthLimiter(80))
    sm.use_technique(angr.exploration_techniques.Explorer)
    function_end_address = base_addr + 0xe60
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
