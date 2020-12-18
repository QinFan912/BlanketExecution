import copy
import ctypes
import os
import subprocess
import sys
import pprint
from collections import defaultdict

from angr.analyses.decompiler.structured_codegen import CConstant

from variable_recover.address_extractor import VariablesAddressExtractor

import angr
from angr.sim_variable import SimRegisterVariable, SimStackVariable


class VariablesValueExtractor:
    def __init__(self, file_name, file_path, save_path, data_path):

        self.file_name = file_name
        self.file_path = file_path
        self.save_path = save_path
        if os.path.exists(self.save_path):
            print('[VariablesAddressExtractor] {} already exists, removed!'.format(self.save_path))
            os.remove(self.save_path)

        self.data_path = data_path
        if os.path.exists(self.data_path):
            print('[VariablesAddressExtractor] {} already exists, removed!'.format(self.data_path))
            os.remove(self.data_path)

        self.not_cover = 0
        self.value_result = dict()

        self.blanket_execution()

    def blanket_execution(self):
        """
        Blanket Execution
        """
        base_addr = 0x4000000

        p = angr.Project(self.file_path, auto_load_libs=False,
                         load_options={
                             'main_opts': {
                                 'base_addr': base_addr
                             }
                         })
        min_addr = p.loader.min_addr
        max_addr = p.loader.max_addr
        print("min_addr:", min_addr)
        print("max_addr:", max_addr)

        cfg = p.analyses.CFG(show_progressbar=True, data_references=True, normalize=True)
        mem_data = cfg.memory_data

        cc = p.analyses.CompleteCallingConventions(recover_variables=True)
        gvar = p.kb.variables['global']._variables
        print("gvar:", gvar)
        gvar_dict = defaultdict(list)

        kb = angr.KnowledgeBase(p)
        funcs = list(cfg.kb.functions.values())
        function_numbers = len(funcs)
        print("function_numbers:", function_numbers)

        # 获取输出特定数据的基本块的信息
        def save_block_info(expr, v, s):
            string_path = '/home/qinfan/PycharmProjects/angr/string_block/'
            if expr == v:
                b = p.factory.block(s.addr)
                info = str(hex(s.addr)) + str(b.instruction_addrs)
                # info = b.pp()
                if info:
                    with open(string_path + self.file_name + '@' + str(v) + '.txt', 'a') as f:
                        f.write(str(info) + '\n')

        # 部分数字到字符串的恢复,大小端的转换
        def string_recovery(x):
            command = "readelf -h " + self.file_path
            back = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            print(back[0].decode())

            if p.arch.memory_endness == 'Iend_LE':
                y = x.to_bytes(4, byteorder='little')
            else:
                y = x.to_bytes(4, byteorder='big')
            return y.decode()

        for func in cfg.kb.functions.values():
            if func.is_simprocedure or func.is_plt:
                # skil all SimProcedures and PLT stubs
                continue
            if func.alignment:
                # skil all aligement functions
                continue

            # if func.name != 'main':
            #     continue

            init_state = p.factory.blank_state(addr=func.addr, mode="fastpath",
                                               add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC,
                                                            angr.options.CALLLESS,
                                                            angr.options.LAZY_SOLVES})

            stack_base_addr = init_state.regs.sp

            sm = p.factory.simgr(init_state, save_unsat=True)

            try:
                dec = p.analyses.Decompiler(func, cfg=cfg)
            except:
                continue

            # convert function blocks to AIL blocks
            clinic = p.analyses.Clinic(func)

            # recover regions
            ri = p.analyses.RegionIdentifier(func, graph=clinic.graph)

            # structure it
            rs = p.analyses.RecursiveStructurer(ri.region)

            # simplify it
            s = p.analyses.RegionSimplifier(rs.result)

            codegen = p.analyses.StructuredCodeGenerator(func, s.result, cfg=cfg)

            # if dec.codegen is None:
            #     continue
            the_kb = dec.clinic.variable_kb
            variable_manager = the_kb.variables[func.addr]
            var = variable_manager.get_variables()

            l = list()
            var_dict = defaultdict(list)
            for k, v in codegen.posmap.items():
                if isinstance(v.obj, CConstant):
                    if isinstance(v.obj.value, int):
                        c = ctypes.c_int32(v.obj.value).value
                        l.append(c)

            # 过滤常量中的地址值......
            # for cons in l:
            #     if not isinstance(cons, int):
            #         continue
            #     if cons in mem_data:
            #         s = init_state.copy()
            #         s.regs._ip = cons
            #         a = s.solver.eval(s.memory.load(addr=cons, size=4),
            #         cast_to=bytes).decode('utf-8', errors='ignore')
            #         l = [a if x == cons else x for x in l]
            #     elif cons >= min_addr:
            #         ob = p.loader.find_object_containing(addr=cons)
            #         if ob:
            #             se = ob.find_section_containing(addr=cons)
            #             if se:
            #                 s = init_state.copy()
            #                 s.regs._ip = cons
            #                 a = s.solver.eval(s.memory.load(addr=cons, size=4),
            #                 cast_to=bytes).decode('utf-8', errors='ignore')
            #                 l = [a if x == cons else x for x in l]
            # l = list(set(l))
            # var_dict['constant'] = l

            for cons in l[::-1]:
                if min_addr <= cons <= max_addr:
                    l.remove(cons)

            l1 = sorted(list(set(l)))
            var_dict['constant'] = l1

            block_nums = 0
            block_list = []
            block_dict = defaultdict(int)

            for b in func.blocks:
                block_list.append(b.addr)
                block_nums += 1

            def track_register(state):
                if state.inspect.reg_write_offset == state.arch.ip_offset:
                    return
                print("state %s is about to do a register write" % state)
                print("write address:", state.solver.eval(state.inspect.reg_write_offset))
                if state.inspect.reg_write_expr.symbolic:
                    print("Expr is symbolic. skip.")
                    return
                print("expr:", state.solver.eval(state.inspect.reg_write_expr))
                expr = state.solver.eval(state.inspect.reg_write_expr)
                # save_block_info(expr, 257, state)
                # save_block_info(expr, 259, state)
                # save_block_info(expr, 371, state)

                for va in var:
                    if isinstance(va, SimRegisterVariable):
                        if state.solver.eval(state.inspect.reg_write_offset) == va.reg:
                            if expr in mem_data:
                                d = state.mem[expr].deref.int.concrete
                                # save_block_info(d, 257, state)
                                # save_block_info(d, 259, state)
                                # save_block_info(d, 371, state)

                                var_dict[va.name].append(d)
                            elif expr >= min_addr:
                                obj = p.loader.find_object_containing(addr=expr)
                                if obj:
                                    sec = obj.find_section_containing(addr=expr)
                                    if sec:
                                        d = state.mem[expr].deref.int.concrete
                                        # save_block_info(d, 257, state)
                                        # save_block_info(d, 259, state)
                                        # save_block_info(d, 371, state)

                                        var_dict[va.name].append(d)
                            else:
                                var_dict[va.name].append(expr)

                            new_list = sorted(list(set(var_dict[va.name])))
                            var_dict[va.name] = new_list

            def track_stack(state):
                print("state %s is about to do a memory write" % state)
                print("The address of the state:", hex(state.addr))
                print("the SP of the state:", state.regs.sp)
                print("write address:", state.inspect.mem_write_address)
                print("expr:", state.inspect.mem_write_expr)  # state.solver.eval(state.inspect.mem_write_expr))
                if state.inspect.mem_write_expr.symbolic:
                    print("Expr is symbolic. skip.")
                    return

                expr = state.solver.eval(state.inspect.mem_write_expr)
                for va in var:
                    if isinstance(va, SimStackVariable):
                        # # 通过dwarf信息恢复变量名
                        # for k, v in variables_offset.items():
                        #     if k == func.name:
                        #         for i in range(len(v)):
                        #             if va.addr == v[i][1]:
                        #                 va.name = v[i][0]
                        #                 print(va.name)
                        if state.solver.eval(state.regs.sp) - state.solver.eval(stack_base_addr) == va.addr:
                            if expr in mem_data:
                                d = state.mem[expr].deref.int.concrete
                                var_dict[va.name].append(d)
                            elif expr >= min_addr:
                                obj = p.loader.find_object_containing(addr=expr)
                                if obj:
                                    sec = obj.find_section_containing(addr=expr)
                                    if sec:
                                        d = state.mem[expr].deref.int.concrete
                                        var_dict[va.name].append(d)
                            else:
                                var_dict[va.name].append(expr)

                            new_list = sorted(list(set(var_dict[va.name])))
                            var_dict[va.name] = new_list

            def track_mem(state):
                print("state %s is about to do a memory write" % state)
                print("The address of the state:", hex(state.addr))
                print("write address:", state.inspect.mem_write_address)
                print("expr:", state.solver.eval(state.inspect.mem_write_expr))
                for gv in gvar:
                    if state.solver.symbolic(state.inspect.mem_write_address):
                        continue
                    if state.solver.eval(state.inspect.mem_write_address) == gv.addr:
                        gvar_dict[gv.name].append(state.solver.eval(state.inspect.mem_write_expr))

            init_state.inspect.b("reg_write", when=angr.BP_AFTER, action=track_register)
            init_state.inspect.b("mem_write", when=angr.BP_AFTER, action=track_stack)

            if gvar:
                init_state.inspect.b("mem_write", when=angr.BP_AFTER, action=track_mem)

            while sm.active:

                # keep one state for each address
                all_actives = defaultdict(list)
                for state in sm.active:
                    if state.regs.ip.symbolic:
                        continue
                    all_actives[state.addr].append(state)
                sm.stashes['active'] = [next(iter(v)) for v in all_actives.values()]

                print(all_actives)
                print(sm.active)

                last_step_addrs = []
                for state in sm.active:
                    block_dict[state.addr] += 1
                    last_step_addrs.append(state.addr)

                for state in sm.active[::-1]:
                    if block_dict[state.addr] > 2:
                        sm.active.remove(state)

                print(sm.active)
                print("#" * 100)
                sm.step()
                print(sm.active)

                # process indirect jumps that are potentially jump tables
                for state_addr in last_step_addrs:
                    if state_addr in cfg.jump_tables:
                        # load all targets
                        jt = cfg.jump_tables[state_addr]
                        entries = set(jt.jumptable_entries)
                        # create a successor for each entry
                        if sm.active + sm.unsat:
                            template_state = next(iter(sm.active + sm.unsat))
                            for ent in entries:
                                print("[.] Creating an active state for jump table entry %#x." % ent)
                                s = template_state.copy()
                                s.regs._ip = ent
                                sm.active.append(s)

                # print(sm.unsat)
                for state in sm.unsat:
                    state.solver.constraints.clear()
                sm.move(from_stash='unsat', to_stash='active')

            # 去除数值重复的变量
            value_set = set()
            result = dict()
            for k, v in var_dict.items():
                if str(v) not in value_set:
                    value_set.add(str(v))
                    result[k] = v
                else:
                    var_dict[k] = None

            self.value_result[func.name] = result
            result_int = copy.deepcopy(result)

            # 字符串的恢复
            for k, v in result.items():
                for index, val in enumerate(v):
                    # 1094795585是'AAAA'的十进制数
                    # 2054847098是'zzzz'的十进制数
                    if 1094795585 <= val <= 2054847098:
                        r = string_recovery(val)
                        v[index] = r

            with open(self.save_path, 'a') as f:
                f.writelines(func.name + ":" + '\n' + str(result) + '\n')

            _result = copy.deepcopy(result_int)
            self.save_value(_result, func.name)

            block_cover = 0
            for dic in block_list:
                if dic in block_dict and block_dict[dic] >= 1:
                    block_cover += 1

            coverage_rate = block_cover / block_nums

            if coverage_rate < 1:
                blocks_diff = set(block_list).difference(set(block_dict))
                print("### Function %s" % func.name)
                print("### The following blocks are not covered:")
                pprint.pprint(list(map(hex, blocks_diff)))
                print("###")
                self.not_cover += 1

    def unified_save_value(self, res, name):
        count = 'b'
        with open(self.data_path, 'a') as f:
            f.write(self.file_name + "@" + name + '\t')
            while len(res.keys()) < 8:
                res[count] = [0]
                count += '1'
            for k, v in res.items():
                while len(v) < 40:
                    v.append(0)
                while len(v) > 40:
                    v = v[:40]
                for i in v:
                    f.write(str(i) + '\t')
            f.write('\n')

    def save_value(self, res, name):
        with open(self.data_path, 'a') as f:
            f.write(self.file_name + '@' + name + '\t')
            for k, v in res.items():
                for i in v:
                    f.write(str(i) + '\t')
            f.write('\n')

# if __name__ == '__main__':
#     file_name = "basename"
#
#     # X86
#     X86_file_path = "/home/qinfan/coreutils/coreutils-X86/src/" + file_name
#     X86_save_path = '/home/qinfan/PycharmProjects/angr/X86-var-texts/' + file_name + "_dec.txt"
#     X86_data_path = '/home/qinfan/PycharmProjects/angr/data/X86/' + file_name + "_data.txt"
#
#     extractor = VariablesValueExtractor(file_name, X86_file_path, X86_save_path, X86_data_path)
#     print(extractor.not_cover)
#     data_dict = extractor.value_result
#     print(data_dict)

# for k, v in extractor.value_result.items():
#     print(k)
#     print(v)
#     for k1, v1 in v.items():
#         print(k1)
#         print(v1)
#         print(type(v1))
