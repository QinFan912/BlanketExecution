import logging

from . import ExplorationTechnique
from ..knowledge_base import KnowledgeBase
from ..knowledge_plugins.functions import Function

l = logging.getLogger(name=__name__)


class LoopSeer(ExplorationTechnique):
    """
    这种探索技术监视探索并维护所有与循环有关的数据。

    主要是使用合理的循环计数近似值来丢弃循环次数过多的状态，将它们放入spinning中，
    如果没有其他可行的状态，则再次将它们取出。
    """

    # 初始化函数,初始化一些必需参数
    def __init__(self, cfg=None, functions=None, loops=None, use_header=False,
                 bound=None, bound_reached=None, discard_stash='spinning',
                 limit_concrete_loops=True):
        """
        :param cfg:                   需要标准化的CFG。
        :param functions:             要分析的包含循环的函数。
        :param loops:                 要分析的特定的一组Loop，如果为None，则运行LoopFinder分析。
        :param use_header:            是否使用基于标头的行程计数器与绑定限制进行比较。
        :param bound:                 限制循环可以执行的迭代次数。
        :param bound_reached:         如果提供的话，应该是采用LoopSeer和succ_state的函数。当循环执行达到给定界限时将被调用。
                                      默认情况下，超过循环限制的状态将被丢弃到discard stash中。
        :param discard_stash:         包含超过循环限制的状态的存储区的名称。
        :param limit_concrete_loops:  如果为False，则如果它是唯一的后继者，则不限制循环后端
                                     （默认为True以保持原始行为）
        """

        super(LoopSeer, self).__init__()
        self.cfg = cfg
        self.functions = functions
        self.bound = bound
        self.bound_reached = bound_reached
        self.discard_stash = discard_stash
        self.use_header = use_header
        self.limit_concrete_loops = limit_concrete_loops
        self.loops = {}
        self.cut_succs = []
        if type(loops) is Loop:
            loops = [loops]

        if type(loops) in (list, tuple) and all(type(l) is Loop for l in loops):
            for loop in loops:
                if loop.entry_edges:
                    self.loops[loop.entry_edges[0][1].addr] = loop

        elif loops is not None:
            raise TypeError("Invalid type for 'loops' parameter!")

    # 重写ExplorationTechnique中的setup函数
    def setup(self, simgr):
        # LoopSeer必须使用标准化的CFG,标准化提供的CFG
        if self.cfg is None:
            cfg_kb = KnowledgeBase(self.project)
            self.cfg = self.project.analyses.CFGFast(kb=cfg_kb, normalize=True)
        elif not self.cfg.normalized:
            l.warning("LoopSeer must use a normalized CFG. Normalizing the provided CFG...")
            self.cfg.normalize()

        # function参数的类型必须是有效的
        funcs = None
        if type(self.functions) in (str, int, Function):
            funcs = [self._get_function(self.functions)]

        elif type(self.functions) in (list, tuple) and all(type(f) in (str, int, Function) for f in self.functions):
            funcs = []
            for f in self.functions:
                func = self._get_function(f)
                if func is not None:
                    funcs.append(func)
            funcs = None if not funcs else funcs

        elif self.functions is not None:
            raise TypeError("Invalid type for 'functions' parameter!")

        # 提取所有的循环,并记录循环开始地址
        if not self.loops:
            loop_finder = self.project.analyses.LoopFinder(kb=self.cfg.kb, normalize=True, functions=funcs)

            for loop in loop_finder.loops:
                if loop.entry_edges:
                    entry = loop.entry_edges[0][1]
                    self.loops[entry.addr] = loop

    # 重写ExplorationTechnique中的filter函数
    def filter(self, simgr, state, **kwargs):
        # 移除cut_succs stash中的state
        if state in self.cut_succs:
            self.cut_succs.remove(state)
            return self.discard_stash
        else:
            return simgr.filter(state, **kwargs)

    # 重写ExplorationTechnique中的successors函数,获取当前state的后继状态
    def successors(self, simgr, state, **kwargs):
        node = self.cfg.model.get_any_node(state.addr)
        if node is not None:
            kwargs['num_inst'] = min(kwargs.get('num_inst', float('inf')), len(node.instruction_addrs))
        succs = simgr.successors(state, **kwargs)

        # 判断后继状态中有没有位于退出循环处的state
        at_loop_exit = False
        for succ_state in succs.successors:
            if succ_state.loop_data.current_loop:
                if succ_state.addr in succ_state.loop_data.current_loop[-1][1]:
                    l.debug("One of the successors: %s is at the exit of the current loop %s", hex(succ_state.addr),
                            succ_state.loop_data.current_loop[-1][0])
                    # 如果有，则令 at_loop_exit = True
                    at_loop_exit = True

        # 对于后级状态中的所有循环
        for succ_state in succs.successors:
            # 处理当前正在运行的循环
            if succ_state.loop_data.current_loop:
                l.debug("Loops currently active are %s", succ_state.loop_data.current_loop)
                # 提取有关循环的信息（[-1]执行最后一个活动循环，[0]执行循环对象）
                loop = succ_state.loop_data.current_loop[-1][0]
                header = loop.entry.addr
                l.debug("Loop currently active is %s with entry %s", loop, hex(header))

                # 当后继状态中有state的地址位于一个循环的开始地址时
                if succ_state.addr == header:
                    continue_addrs = [e[0].addr for e in loop.continue_edges]
                    # 如果只有一个后继者，则该循环是“具体的”,我们希望不切掉具体的循环，因为这可能会过早地终止路径，即使不会发生状态爆炸。
                    # 当要限制具体循环时或者后级状态个数大于１时
                    if self.limit_concrete_loops or len(succs.successors) > 1:
                        # 如果前一个状态包含一个地址在continue_addrs内，则也就是“已经遍历了Continue边缘”，表明在后边缘进行了一次迭代。
                        if succ_state.history.addr in continue_addrs:
                            # 在succ_state.addr处的back_edge_trip_counts＋１
                            l.debug("Continue edge traversed, incrementing back_edge_trip_counts for addr at %s",
                                    hex(succ_state.addr))
                            succ_state.loop_data.back_edge_trip_counts[succ_state.addr][-1] += 1

                        # 在succ_state.addr处的header_trip_counts＋１
                        l.debug("Continue edge traversed, incrementing header_trip_counts for addr at %s",
                                hex(succ_state.addr))
                        succ_state.loop_data.header_trip_counts[succ_state.addr][-1] += 1

                # 当后级状态的地址在当前循环的出口节点中时
                elif succ_state.addr in succ_state.loop_data.current_loop[-1][1]:
                    # 就终止循环，将其从当前活动中弹出。
                    l.debug("Deactivating loop at %s because hits the exit node", hex(succ_state.addr))
                    succ_state.loop_data.current_loop.pop()

                # 当后继状态中有位于退出循环处的state时
                elif at_loop_exit:
                    # 在循环退出时，在succ_state.addr处back_edge_trip_counts+1
                    if not self.limit_concrete_loops and len(succs.successors) > 1:
                        l.debug("At loop exit, incrementing back_edge_trip_counts for addr at %s", hex(succ_state.addr))
                        succ_state.loop_data.back_edge_trip_counts[succ_state.addr][-1] += 1

                # 如果我们为符号/具体循环设置了界限
                if self.bound is not None and succ_state.loop_data.current_loop:
                    counts = 0
                    # 判断是否到达界限
                    if self.use_header:
                        counts = succ_state.loop_data.header_trip_counts[header][-1]
                    else:
                        if succ_state.addr in succ_state.loop_data.back_edge_trip_counts:
                            counts = succ_state.loop_data.back_edge_trip_counts[succ_state.addr][-1]
                    # 如果计数表明已经超过了循环次数的界限
                    if counts > self.bound:
                        # 如果提供了bound_reached函数，就调用他
                        if self.bound_reached is not None:
                            self.bound_reached(self, succ_state)
                        # 否则，将当前后级状态直接移除
                        else:
                            self.cut_succs.append(succ_state)

                l.debug("%s back edge based trip counts %s", state, state.loop_data.back_edge_trip_counts)
                l.debug("%s header based trip counts %s", state, state.loop_data.header_trip_counts)
            else:
                l.debug("No loop are currently active at %s", hex(succ_state.addr))

            # 当检测到循环入口时，在嵌套循环的情况下，希望在进行内部循环之前先处理外部循环。
            if succ_state.addr in self.loops and not self._inside_current_loops(succ_state):
                loop = self.loops[succ_state.addr]
                header = loop.entry.addr
                l.debug("Activating loop %s for state at %s", loop, hex(succ_state.addr))
                exits = [e[1].addr for e in loop.break_edges]

                succ_state.loop_data.back_edge_trip_counts[header].append(0)
                if not self.limit_concrete_loops:
                    for node in loop.body_nodes:
                        succ_state.loop_data.back_edge_trip_counts[node.addr].append(0)
                # 保存有关succ状态的当前活动循环的信息
                succ_state.loop_data.header_trip_counts[header].append(1)
                succ_state.loop_data.current_loop.append((loop, exits))
        return succs

    # pylint: disable=R0201
    def _inside_current_loops(self, succ_state):
        current_loops_addrs = [x[0].entry.addr for x in succ_state.loop_data.current_loop]
        if succ_state.addr in current_loops_addrs:
            return True
        return False

    def _get_function(self, func):
        f = None
        if type(func) is str:
            f = self.cfg.kb.functions.function(name=func)
            if f is None:
                l.warning("Function '%s' doesn't exist in the CFG. Skipping...", func)

        elif type(func) is int:
            f = self.cfg.kb.functions.function(addr=func)
            if f is None:
                l.warning("Function at 0x%x doesn't exist in the CFG. Skipping...", func)

        elif type(func) is Function:
            f = func

        return f


from ..analyses.loopfinder import Loop
