import angr
import sys
import claripy


def main(argv):
    base_addr = 0x4000000
    p = angr.Project("/home/qinfan/Ccode/test", auto_load_libs=False,
                     load_options={
                        'main_opts': {
                            'base_addr': base_addr
                        }
                     })

    start_addr = base_addr + 0xe61
    final_addr = base_addr + 0xf32

    next_addr = start_addr

    while next_addr <= final_addr:
        state = p.factory.blank_state(addr=next_addr)
        sm = p.factory.simgr(state)
        print(sm)
        block = p.factory.block(next_addr)
        add_addr = block.size
        instructions = block.instructions
        print(instructions, add_addr)
        print(block)
        sm.step()

        if block.size == 0:
            next_addr = next_addr + add_addr + 1
        else:
            next_addr += add_addr

    print("yes")


if __name__ == "__main__":
    main(sys.argv)
