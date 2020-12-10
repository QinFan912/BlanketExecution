from . import ExplorationTechnique
from .common import condition_to_lambda
from .. import sim_options

import logging

l = logging.getLogger(name=__name__)


class Explorer(ExplorationTechnique):
    """
    向前拖动stash(最多n次或者直到找到"num_find"个满足状态），寻找满足"find"条件的状态，
    避免"avoid"条件，将找到的状态存储到"find_stash"，将避免的状态存储到"avoid_stash"。

    "find"和"avoid"状态可以是以下任意一种：
    - 一个查找地址
    - 要查找的一个地址集合或地址列表
    - 一个函数，这个函数将state作为输入，并且返回是否满足条件

    如果将Angr生成的cfg作为参数传给"cfg"变量，并且"find"参数是set/list/单个地址的话，
    如果你在到达成功的状态的路径上面，有一个状态是失败的状态，那么这个状态就被提前抛弃

    如果“ find”或“ avoid”参数是返回布尔值的函数，并且路径触发了这两个条件，
    则除非“ avoid_priority”设置为True，否则它将被添加到find stash中。
    """

    # 初始化一些必需的参数
    def __init__(self, find=None, avoid=None, find_stash='found', avoid_stash='avoid', cfg=None, num_find=1,
                 avoid_priority=False):
        super(Explorer, self).__init__()
        self.find, static_find = condition_to_lambda(find)
        self.avoid, static_avoid = condition_to_lambda(avoid)
        self.find_stash = find_stash
        self.avoid_stash = avoid_stash
        self.cfg = cfg
        self.ok_blocks = set()
        self.num_find = num_find
        self.avoid_priority = avoid_priority

        self._extra_stop_points = (static_find or set()) | (static_avoid or set())
        self._unknown_stop_points = static_find is None or static_avoid is None
        self._warned_unicorn = False

        # TODO: This is a hack for while CFGFast doesn't handle procedure continuations
        from .. import analyses
        # CFGFast不适用于当前explorer方法了，禁用CFGFast
        if isinstance(cfg, analyses.CFGFast):
            l.error("CFGFast is currently inappropriate for use with Explorer.")
            l.error("Usage of the CFG has been disabled for this explorer.")
            self.cfg = None

        # 当cfg不为空时
        if self.cfg is not None:
            avoid = static_avoid or set()

            # find中的地址必须是静态的，如果不是的话表明当前cfg不可用
            if not static_find:
                l.error("You must provide at least one 'find' address as a number, "
                        "set, list, or tuple if you provide a CFG.")
                l.error("Usage of the CFG has been disabled for this explorer.")
                self.cfg = None
                return

            # avoid中的address必需在cfg中能够得到
            for a in avoid:
                if cfg.model.get_any_node(a) is None:
                    l.warning("'Avoid' address %#x not present in CFG...", a)

            # find中的address也必需在cfg中能够得到
            queue = []
            for f in static_find:
                nodes = cfg.model.get_all_nodes(f)
                if len(nodes) == 0:
                    l.warning("'Find' address %#x not present in CFG...", f)
                else:
                    queue.extend(nodes)

            # 这是从find的地址出发，后向搜索block，直到找到路径的起始点start，
            # 也就是后向搜索所有的start，使得start能够到达find的地址
            seen_nodes = set()
            while len(queue) > 0:
                n = queue.pop()
                if id(n) in seen_nodes:
                    continue
                if n.addr in avoid:
                    continue
                self.ok_blocks.add(n.addr)
                seen_nodes.add(id(n))
                queue.extend(n.predecessors)

            if len(self.ok_blocks) == 0:
                l.error("No addresses could be validated by the provided CFG!")
                l.error("Usage of the CFG has been disabled for this explorer.")
                self.cfg = None
                return

            # 提醒要确保传入的CFG是完整的，提供不完整的CFG将导致一些可行路径的丢失
            l.warning("Please be sure that the CFG you have passed in is complete.")
            l.warning("Providing an incomplete CFG can cause viable paths to be discarded!")

    # 重写ExplorationTechnique中的setup函数,
    # 初始化find_stash和avoid_stash为空
    def setup(self, simgr):
        if not self.find_stash in simgr.stashes: simgr.stashes[self.find_stash] = []
        if not self.avoid_stash in simgr.stashes: simgr.stashes[self.avoid_stash] = []

    # 重写ExplorationTechnique中的step函数,默认是对active stash的操作
    def step(self, simgr, stash='active', **kwargs):
        # 将find和avoid添加到停止运行的set中去，便于我们搜索和停止搜索某些地址
        base_extra_stop_points = set(kwargs.pop("extra_stop_points", []))
        return simgr.step(stash=stash, extra_stop_points=base_extra_stop_points | self._extra_stop_points, **kwargs)

    # 分类函数，判断给定地址是否可到达，可到达就放到find_stash中，否则放在avoid_stash中
    def _classify(self, addr, findable, avoidable):
        if self.avoid_priority:
            if avoidable and (avoidable is True or addr in avoidable):
                return self.avoid_stash
            elif findable and (findable is True or addr in findable):
                return self.find_stash
        else:
            if findable and (findable is True or addr in findable):
                return self.find_stash
            elif avoidable and (avoidable is True or addr in avoidable):
                return self.avoid_stash
        return None

    # 重写ExplorationTechnique中的filter函数，主要看_filter_inner函数
    def filter(self, simgr, state, **kwargs):
        stash = self._filter_inner(state)
        if stash is None:
            return simgr.filter(state, **kwargs)
        return stash

    # 过滤函数，判断当前state是可到达还是不可到达的
    def _filter_inner(self, state):
        # 使用unicorn的时候，可能会步过匹配的条件而不停止，这个只会提醒一次
        if self._unknown_stop_points and sim_options.UNICORN in state.options and not self._warned_unicorn:
            l.warning("Using unicorn with find/avoid conditions that are a lambda (not a number, set, tuple or list)")
            l.warning("Unicorn may step over states that match the condition (find or avoid) without stopping.")
            self._warned_unicorn = True

        findable = self.find(state)
        avoidable = self.avoid(state)

        if not findable and not avoidable:
            # 如果提供了CFG，并且当前状态还在cfg中，当前地址不在可行的block中，就返回avoid_stash
            if self.cfg is not None and self.cfg.model.get_any_node(state.addr) is not None:
                if state.addr not in self.ok_blocks:
                    return self.avoid_stash
            return None

        stash = self._classify(state.addr, findable, avoidable)
        if stash is not None:
            return stash

        return None

    # 重写ExplorationTechnique中的complete函数，
    # 当find_stash长度大于等于num_find的时候表示执行完成
    def complete(self, simgr):
        return len(simgr.stashes[self.find_stash]) >= self.num_find
