import angr
from angr.analyses.decompiler.condition_processor import ConditionProcessor
import ailment

from blanket_execution import BlanketExecution

from collections import OrderedDict
import functools
import logging
import tqdm

logging.root.setLevel(logging.ERROR)


class BlanketExecutionTrace(BlanketExecution):

    def __init__(self, binary_fpath, save_dir):
        super().__init__()
        self.load(binary_fpath)
        self.prepare_stuffs()
        self.resilience = False

        self.save_dir = save_dir

    def _convert_and_clinic(self, func):

        # cail stands `ail after clinic`
        self.vex_to_cail = OrderedDict()
        self.vex_to_cailstr = OrderedDict()
        self.idx_to_ail = OrderedDict()

        ail_mgr = ailment.Manager(arch=self.proj.arch)

        # convert vex to ail
        for block in func.blocks:
            ail_block = ailment.IRSBConverter.convert(block.vex, ail_mgr)
            for stmt in ail_block.statements:
                if "vex_block_addr" not in stmt.tags:
                    continue
                idx_addr = "%#x@%s" % (
                    stmt.tags["vex_block_addr"], stmt.idx)
                self.idx_to_ail[idx_addr] = stmt

        # clinic deals
        try:
            clinic = self.proj.analyses.Clinic(func)
        except Exception as e:
            print(e)
            return False

        if clinic.graph is None:
            print(func.name)
            return False

        for ail_block in clinic.graph:
            for stmt in ail_block.statements:
                if "vex_block_addr" not in stmt.tags:
                    continue
                tag_addr = "%#x@%s" % (
                    stmt.tags["vex_block_addr"], stmt.tags["vex_stmt_idx"])
                self.vex_to_cail[tag_addr] = stmt
                self.vex_to_cailstr[tag_addr] = str(stmt)
        
        return True
    
    def execute(self):

        # load check
        assert self.proj is not None
        assert self.cfg is not None

        for func in tqdm.tqdm(self.cfg.kb.functions.values()):

            if self.func_filter(func):
                continue

            self.executing_func = func

            if not self._convert_and_clinic(func):
                continue

            self._execute_func(func)

            self.save_traces(os.path.join(self.save_dir, "%s.txt" % func.name))

    def func_filter(self, func):
        # if func.name not in ["decode_switches"]:
        #     return True
        return (True if func.is_simprocedure or
                func.is_plt or func.alignment else False)

    def set_breakpoints(self, state: "angr.sim_state.SimState"):
        state.inspect.b("statement", angr.BP_AFTER, action=self._trace)

    def _trace(self, state):

        block_addr = state.scratch.bbl_addr
        stmt_idx = state.inspect.statement
        # the vex block addr and stmt index in ail tags
        tag_addr = "%#x@%d" % (block_addr, stmt_idx)

        if tag_addr not in self.vex_to_cail:
            return

        cail = self.vex_to_cail[tag_addr]
        self.trace_handler.handle_stmt(cail, state, self.idx_to_ail)

    def save_traces(self, save_fpath):

        def compare(a, b):
            block_addr_a, stmt_idx_a = a.split("@")
            block_addr_b, stmt_idx_b = b.split("@")
            if int(block_addr_a, 16) > int(block_addr_b, 16):
                return 1
            elif int(block_addr_a, 16) < int(block_addr_b, 16):
                return -1
            elif int(stmt_idx_a) > int(stmt_idx_b):
                return 1
            elif int(stmt_idx_a) < int(stmt_idx_b):
                return -1
            else:
                return 0

        tag_addrs = sorted(
            self.vex_to_cail.keys(), key=functools.cmp_to_key(compare))

        with open(save_fpath, "w") as f:
            for tag_addr in tag_addrs:
                # if tag_addr.endswith("-2"):
                #     continue
                cail = self.vex_to_cail[tag_addr]
                cail_str = self.vex_to_cailstr[tag_addr]
                markup_ail = self.marker_converter.convert(cail)
                f.write("%s | %s | %s\n" % (tag_addr, cail_str, markup_ail))


if __name__ == "__main__":

    import time
    import os
    import shutil

    start = time.time()

    binary_fname = "unexpand"
    save_dir = os.path.join("./", "%s_trace" % binary_fname)

    if os.path.exists(save_dir):
        shutil.rmtree(save_dir)
    os.mkdir(save_dir)

    blanket_exe = BlanketExecutionTrace(binary_fname, save_dir)
    blanket_exe.execute()

    print("%.4f s" % (time.time()-start))
