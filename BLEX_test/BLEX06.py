import angr
import sys


def main(argv):
    base_addr = 0x4000000
    p = angr.Project("/home/qinfan/Ccode/test/cp", auto_load_libs=False,
                     load_options={
                        'main_opts': {
                            'base_addr': base_addr
                        }
                     })

    with open('/home/qinfan/PycharmProjects/angr_test/BLEX_test/function.txt', 'r') as f:
        function = f.readlines()
    func = list(function)
    max = len(func)
    print(max/2)

    i = 0
    while i < max - 1:
        start_addr = int(func[i])
        end_addr = int(func[i + 1]) - 1
        i += 2

        function_start_address = base_addr + start_addr
        function_end_address = base_addr + end_addr
        # print(function_start_address, function_end_address)

        next_addr = function_start_address
        # print(next_addr)
        block_nums = 0
        while next_addr <= function_end_address:
            block = p.factory.block(next_addr)
            block_nums += 1
            add_addr = block.size
            next_addr += add_addr
        print(block_nums)

        init_state = p.factory.blank_state(addr=function_start_address,
                                           add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC})

        sm = p.factory.simgr(init_state)

        count = 0
        while sm.active:
            sm.step()
            count += 1
            print(sm)
            print("Active state:", sm.active)
            if count >= block_nums:
                break

            if len(sm.active) >= 5:
                del sm.active[5:]
                # sm.drop()


if __name__ == "__main__":
    main(sys.argv)
