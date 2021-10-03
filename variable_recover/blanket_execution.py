import angr
import angr.errors as Errors
from angr.engines import UberEngine

from func_timeout import func_set_timeout
from func_timeout import FunctionTimedOut
import random
import sys


class NormalizedCFGEngine(UberEngine):
    """
    A small patch for UberEngine which make simulate execute on a normalized IRSB.
    """

    def __init__(self, cfg, project):
        super().__init__(project)

        self.irsb_mapping = {}
        for func in cfg.kb.functions.values():
            self.irsb_mapping.update(
                {b.addr: b.vex for b in func.blocks if b.size != 0})

    def process_successors(self, successors, irsb=None, **kwargs):
        irsb = self.irsb_mapping.get(successors.addr, None)
        return super().process_successors(successors, irsb=irsb, **kwargs)


class BlanketExecutionBase:

    def __init__(self):
        self.proj = None
        self.cfg = None
        self.engine = None

        self.max_step = 200
        self.resilience = True

        self.state_options = {
            angr.options.UNDER_CONSTRAINED_SYMEXEC,
            # angr.options.CALLLESS,
            angr.options.LAZY_SOLVES,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }

    def load(self, binary_fpath, load_options=None):

        if load_options is None:
            load_options = {
                "auto_load_libs": False,
                "main_opts": {"base_addr": 0x400000}
                }

        self.proj: "angr.Project" = angr.Project(
            binary_fpath, load_options=load_options)
        self.cfg: "angr.analyses.CFG" = self.proj.analyses.CFG(
            show_progressbar=True, data_references=True, normalize=True)
        self.engine = NormalizedCFGEngine(self.cfg, self.proj)

    def func_filter(self, func):
        return (True if func.is_simprocedure or
                func.is_plt or func.alignment else False)

    def execute(self):

        # load check
        assert self.proj is not None
        assert self.cfg is not None

        for func in self.cfg.kb.functions.values():

            if self.func_filter(func):
                continue

            self.executing_func = func
            self._execute_func(func)

    @func_set_timeout(20 if not sys.gettrace() else 60*10)
    def _step(self, simgr):
        simgr.step(engine=self.engine)

    def _execute_func(self, func):

        init_state = self.proj.factory.blank_state(
            addr=func.addr, mode="fastpath", add_options=self.state_options)

        # self.process_init_state(init_state)
        self.set_breakpoints(init_state)

        self.simgr = self.proj.factory.simgr(
            init_state, save_unsat=True, resilience=self.resilience)

        executed_blocks = []

        for _ in range(self.max_step):

            try:
                self._step(self.simgr)
            except FunctionTimedOut as e:
                print(e)
            except Errors.SimEngineError as e:
                print(e)
            except Errors.AngrExitError as e:
                print(e)
            except Errors.SimValueError as e:
                print(e)
            except Exception as e:
                print(e)
                raise e

            updated_stashes = self.process_stashes(self.simgr.stashes)
            self.simgr._stashes.update(updated_stashes)

            for state in self.simgr.active:
                if state.addr in executed_blocks:
                    self.simgr.active.remove(state)
                else:
                    executed_blocks.append(state.addr)

            if not self.simgr.active:
                break

    def set_breakpoints(self, state):
        raise NotImplementedError

    # def process_init_state(self, state):
    #     raise NotImplementedError

    def process_stashes(self, stashes):
        raise NotImplementedError


class BlanketExecution(BlanketExecutionBase):

    def __init__(self):
        super().__init__()

        self.skip_gprs = ["rbp", "rsp", "rip"]

        self.unsat_limit = 10
        self.drop_unsat_limit = 3

        self.unsatCounter = {}
        self.addr2func = {}
        self.cllstack_limts = {}
        self.insns_drop_unsat = []
    
    def prepare_stuffs(self):

        for func in self.cfg.kb.functions.values():

            self.addr2func[func.addr] = func
            sorted_blocks = sorted([(b.addr, b) for b in func.blocks])

            callstack_limit = max(int(100 / (len(sorted_blocks)+1)), 5)
            self.cllstack_limts[func.addr] = callstack_limit

            pre_mnemonic = "_"
            for _, block in sorted_blocks:
                for insn in block.capstone.insns:
                    # in the case of `["call", "jmp", "jz", "je", "jne"]`
                    if pre_mnemonic == "call" or pre_mnemonic.startswith("j"):
                        self.insns_drop_unsat.append(insn.address)
                    pre_mnemonic = insn.mnemonic

    def set_breakpoints(self, state):
        raise NotImplementedError

    # def process_init_state(self, state):
    #     # random initialize general purpose registers
    #     for reg in state.arch.register_list:
    #         random_val = random.randint(0, 0x7fffffffffffffff)
    #         if reg.general_purpose and reg.name not in self.skip_gprs:
    #             setattr(state.regs, reg.name, random_val)
    #         if reg.floating_point:
    #             setattr(state.regs, reg.name, random_val)

    def process_stashes(self, stashes):
        """
        A dirty process, not pleasing...
        """

        # process unsat state
        for state in stashes["unsat"]:
            func = self.executing_func
            if state.addr < func.addr or state.addr >= func.addr + func.size:
                continue
            unsat_count = self.unsatCounter.get(state.addr, 0)
            if unsat_count > self.unsat_limit:
                continue
            if state.addr in self.insns_drop_unsat \
                    and unsat_count > self.drop_unsat_limit:
                continue
            state.solver.constraints.clear()
            stashes["active"].append(state)
            self.unsatCounter[state.addr] = unsat_count + 1

        # remove repeated address state
        satet_addrs = []
        for state in stashes["active"]:
            if state.addr not in satet_addrs:
                satet_addrs.append(state.addr)
            else:
                stashes["active"].remove(state)

        # add jump address state
        jump_states = []
        for state in stashes["active"]:
            if state.addr not in self.cfg.jump_tables:
                continue
            jt = self.cfg.jump_tables[state.addr]
            entries = set(jt.jumptable_entries)
            for entry in entries:
                jump_state = state.copy()
                jump_state.regs._ip = entry
                jump_states.append(jump_state)
        stashes["active"] += jump_states

        for state in stashes["active"]:

            # `No bytes in memory for block starting at 0x0.``
            if state.addr == 0x0:
                stashes["active"].remove(state)
                continue

            # Callstack depth limit.
            callstack_limit = self.cllstack_limts[self.executing_func.addr]
            if len(state.callstack) > callstack_limit:
                stashes["active"].remove(state)
                continue

            # skip meaningless function
            if state.addr in self.addr2func:
                func = self.addr2func[state.addr]
                if self.func_filter(func):
                    stashes["active"].remove(state)
                    continue

        # sorted states make execute reproduceable
        stashes["active"] = sorted(stashes["active"], key=lambda x: x.addr)

        return stashes
