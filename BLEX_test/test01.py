from collections import Iterable, defaultdict

import angr
import sys

from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimMemoryVariable


def main(argv):
    base_addr = 0x4000000
    p = angr.Project("/home/qinfan/coreutils/coreutils-8.32/src/cp",
                     load_options={
                         'auto_load_libs': False,
                         'main_opts': {
                             'base_addr': base_addr
                         }
                     })

    init_state = p.factory.entry_state()
    print(init_state.regs.rbp)
    stack_base_addr = init_state.regs.rsp
    print(stack_base_addr)

    sm = p.factory.simgr(init_state)

    cfg = p.analyses.CFG()

    cc = p.analyses.CompleteCallingConventions(recover_variables=True)
    gvar = p.kb.variables['global']._variables
    print(gvar)
    print("!!"*50)
    for gv in gvar:
        print(gv.name,hex(gv.addr))

    print("!!"*50)
    # p.analyses.CompleteCallingConventions(recover_variables=True)

    kb = angr.KnowledgeBase(p)

    func = list(cfg.kb.functions.values())
    print(func)
    function_numbers = len(func)
    print(function_numbers)

    var_dict = defaultdict(list)
    gvar_dict = defaultdict(list)

    print(func[0])
    v = p.analyses.VariableRecoveryFast(func[0], kb=kb)
    print(v)
    var_manager = v.variable_manager[func[0].addr]
    print(var_manager)
    # print(gvar_manager)
    var = var_manager.get_variables()
    print(var)
    print(len(var))

    for va in var:
        # if isinstance(va, SimRegisterVariable):
        #     print(va.name, va.reg)
        if isinstance(va, SimStackVariable):
            print(va.name, va.addr)
        # if isinstance(va,SimMemoryVariable):
        #     print(va)
    print("--"*50)
    for va in var:
        if type(va) == SimMemoryVariable:
            print(va.name, va.addr)

        if type(va) == SimStackVariable:
            print(va.name, va.addr)

    print("$$" * 100)

    def track_register(state):
        print("state %s is about to do a register write" % state)
        print("write address:", state.solver.eval(state.inspect.reg_write_offset))
        print("expr:", state.solver.eval(state.inspect.reg_write_expr))
        for va in var:
            if isinstance(va, SimRegisterVariable):
                if state.solver.eval(state.inspect.reg_write_offset) == va.reg:
                    var_dict[va.name].append(state.solver.eval(state.inspect.reg_write_expr))

    def track_stack(state):
        print("state %s is about to do a memory write" % state)
        print("the SP of the state:", state.regs.rsp)
        print("write address:", state.inspect.mem_write_address)
        print("expr:", state.solver.eval(state.inspect.mem_write_expr))
        for va in var:
            if isinstance(va, SimStackVariable):
                if state.solver.eval(state.regs.rsp) - state.solver.eval(stack_base_addr) == va.addr:
                    var_dict[va.name].append(state.solver.eval(state.inspect.mem_write_expr))
        for ga in gvar:
            if state.inspect.mem_write_address == ga.addr:
                gvar_dict[ga.name].append(state.solver.eval(state.inspect.mem_write_expr))
            # if type(va) == SimStackVariable:
            #     if state.solver.eval(state.regs.rsp) - state.solver.eval(stack_base_addr) == va.addr:
            #         var_dict[va.name].append(state.solver.eval(state.inspect.mem_write_expr))
            # if type(va) == SimMemoryVariable:
            #     if state.addr == va.addr:
            #         var_dict[va.name].append(state.solver.eval(state.inspect.mem_write_expr))

    init_state.inspect.b("reg_write", when=angr.BP_AFTER, action=track_register)
    init_state.inspect.b("mem_write", when=angr.BP_AFTER, action=track_stack)
    # init_state.step()
    for i in range(300):
        sm.step()

    print(var_dict)
    print(gvar_dict)


'''
    for func in cfg.kb.functions.values():
        if func.is_simprocedure or func.is_plt:
            # skil all SimProcedures and PLT stubs
            continue
        start_addr = func.addr
        end_addr = None
        for b in func.blocks:
            if end_addr is None or b.addr + b.size > end_addr:
                end_addr = b.addr + b.size
        if end_addr is None:
            continue

        function_start_address = start_addr
        function_end_address = end_addr - 1

        next_addr = function_start_address
        block_nums = 0
        block_list = []

        while next_addr <= function_end_address:
            block = p.factory.block(next_addr)
            block_list.append(block.addr)
            block_nums += 1
            add_addr = block.size
            next_addr += add_addr
        print(block_nums)
        print(list(map(hex, block_list)))

        v = p.analyses.VariableRecovery(func, kb=kb)
        print("*" * 100)
        for block_addr in block_list:
            s = v.get_variable_definitions(block_addr)
            print(s)
        print("*" * 100)
'''

if __name__ == "__main__":
    main(sys.argv)
