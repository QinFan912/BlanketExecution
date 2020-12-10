import logging
from itertools import islice

from . import ExplorationTechnique

l = logging.getLogger(name=__name__)


class DrillerCore(ExplorationTechnique):
    """
    一种象征性地跟随输入以寻找新状态转换的探索技术。

    它必须与Tracer探索技术一起使用。 结果放入“diverted”存储区。

    """

    # 初始化函数,初始化一些必需参数
    def __init__(self, trace, fuzz_bitmap=None):
        """
        初始化函数参数:
        trace      : 基本块跟踪。The basic block trace.
        fuzz_bitmap: AFL的状态转换位图。 默认说每个转换都值得满足。
        """

        super(DrillerCore, self).__init__()
        self.trace = trace
        self.fuzz_bitmap = fuzz_bitmap or b"\xff" * 65536

        # 遇到的基本块转换的集合
        self.encounters = set()

    # 重写ExplorationTechnique中的setup函数
    def setup(self, simgr):
        self.project = simgr._project

        # 使用已知状态转换更新encounters。
        self.encounters.update(zip(self.trace, islice(self.trace, 1, None)))

    # 重写ExplorationTechnique中的step函数,默认是对active stash的操作
    def step(self, simgr, stash='active', **kwargs):
        simgr.step(stash=stash, **kwargs)

        # 模仿AFL的索引编制方案,
        # 如果存在missed stash并且missed stash不为空
        if 'missed' in simgr.stashes and simgr.missed:
            # 先找到已经存在的转换
            prev_addr = simgr.one_missed.history.bbl_addrs[-1]
            prev_loc = prev_addr
            prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
            prev_loc &= len(self.fuzz_bitmap) - 1
            prev_loc = prev_loc >> 1

            for state in simgr.missed:
                cur_loc = state.addr
                cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                cur_loc &= len(self.fuzz_bitmap) - 1

                hit = bool(self.fuzz_bitmap[cur_loc ^ prev_loc] ^ 0xff)

                transition = (prev_addr, state.addr)
                mapped_to = self.project.loader.find_object_containing(state.addr).binary

                l.debug("Found %#x -> %#x transition.", transition[0], transition[1])

                # 如果hit不是false,transition不在已知状态转换的集合中,
                # state不是unsat并且mapped_to不是'cle##externs'这种形式,
                # 就移除该state的预约束
                if not hit and transition not in self.encounters and not self._has_false(
                        state) and mapped_to != 'cle##externs':
                    state.preconstrainer.remove_preconstraints()

                    # 如果当前state的约束是可满足的
                    if state.satisfiable():
                        # 表示找到了全新的状态转换,然后把该state添加到diverted stash中,
                        # 并把找到的transition添加到已知的转换集合中
                        l.debug("Found a completely new transition, putting into 'diverted' stash.")
                        simgr.stashes['diverted'].append(state)
                        self.encounters.add(transition)

                    # 如果当前state的约束是不可满足的,说明state在哪个地址是不可满足的
                    else:
                        l.debug("State at %#x is not satisfiable.", transition[1])

                # 如果state是unsat,说明该state即使在删除预约束后也是不可满足的
                elif self._has_false(state):
                    l.debug("State at %#x is not satisfiable even remove preconstraints.", transition[1])

                # 最后一种情况则表明该转换是已经遇到过的
                else:
                    l.debug("%#x -> %#x transition has already been encountered.", transition[0], transition[1])

        return simgr

    @staticmethod
    def _has_false(state):
        # 在删除了预约束后，也要检查状态是否是unsat的
        claripy_false = state.solver.false
        if state.scratch.guard.cache_key == claripy_false.cache_key:
            return True

        for c in state.solver.constraints:
            if c.cache_key == claripy_false.cache_key:
                return True

        return False
