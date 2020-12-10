import angr
import sys
import claripy


def main(argv):
    p = angr.Project("/home/qinfan/study/angr_ctf-master/dist/06_angr_symbolic_dynamic_memory")
    entry_addr = p.entry
    start_addr = 0x080483B0
    final_addr = 0x080489bb  # 08048817
    min_addr = p.loader.min_addr
    max_addr = p.loader.max_addr
    print("{:x} {:x} {:x} {:x}".format(min_addr, max_addr, entry_addr, final_addr))

    next_addr = entry_addr

    while next_addr <= final_addr:
        state = p.factory.blank_state(addr=next_addr)
        sm = p.factory.simgr(state)
        block = p.factory.block(next_addr)
        add_addr = block.size
        instructions = block.instructions
        instructions_addr = block.instruction_addrs
        print(instructions, add_addr)
        print(instructions_addr)
        i = 0
        while i < instructions:
            sm.explore(find=instructions_addr[i])
            if sm.found:
                i += 1
            else:
                print("No")
        print(i)
        print(block)

        if block.size == 0:
            next_addr = next_addr + add_addr + 1
        else:
            next_addr += add_addr

    print("yes")


if __name__ == "__main__":
    main(sys.argv)
