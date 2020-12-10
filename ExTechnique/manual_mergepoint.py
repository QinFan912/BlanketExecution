import logging

from . import ExplorationTechnique

l = logging.getLogger(name=__name__)


class ManualMergepoint(ExplorationTechnique):
    # 初始化函数,初始化一些必需参数
    def __init__(self, address, wait_counter=10):
        super(ManualMergepoint, self).__init__()
        self.address = address
        self.wait_counter_limit = wait_counter
        self.wait_counter = 0
        self.stash = 'merge_waiting_%#x_%x' % (self.address, id(self))
        self.filter_marker = 'skip_next_filter_%#x' % self.address

    # 重写ExplorationTechnique中的setup函数
    def setup(self, simgr):
        # 将合并states时需要的stash初始化为空
        simgr.stashes[self.stash] = []

    # 重写ExplorationTechnique中的filter函数
    def filter(self, simgr, state, **kwargs):
        if self.filter_marker not in state.globals:
            if state.addr == self.address:
                self.wait_counter = 0
                return self.stash

        return simgr.filter(state, **kwargs)

    # 标记哪个state不需要过滤
    def mark_nofilter(self, simgr, stash):
        for state in simgr.stashes[stash]:
            state.globals[self.filter_marker] = True

    # 标记哪个state需要过滤
    def mark_okfilter(self, simgr, stash):
        for state in simgr.stashes[stash]:
            state.globals.pop(self.filter_marker)

    # 重写ExplorationTechnique中的step函数,默认是对active stash的操作
    def step(self, simgr, stash='active', **kwargs):
        # 如果合并需要的stash长度为1且active stash长度为0,
        # 将合并需要的stash中的state移到active中
        if len(simgr.stashes[self.stash]) == 1 and len(simgr.stashes[stash]) == 0:
            simgr = simgr.move(self.stash, stash)

        # 运行step操作执行所有分析
        simgr = simgr.step(stash=stash, **kwargs)
        # self.mark_okfilter(simgr, stash)

        # 如果没有state在等待,即active为空，则无事可做
        if len(simgr.stashes[self.stash]) == 0:
            return simgr

        # wait_counter计数加一
        self.wait_counter += 1

        # 看看是否该合并了（超出活动范围或达到了等待限制）
        # 当没达到合并条件时,无事可做
        if len(simgr.stashes[stash]) != 0 and self.wait_counter < self.wait_counter_limit:
            return simgr

        # self.mark_nofilter(simgr, self.stash)

        # 如果确实知道要合并的状态，则将两者合并
        if len(simgr.stashes[self.stash]) == 1:
            simgr.move(self.stash, stash)
            return simgr

        # 通过唯一的调用堆栈进行手动合并
        l.info("Merging %d states at %#x", len(simgr.stashes[self.stash]), self.address)
        num_unique = 0
        while len(simgr.stashes[self.stash]):
            num_unique += 1
            exemplar_callstack = simgr.stashes[self.stash][0].callstack
            simgr.move(self.stash, 'merge_tmp', lambda s: s.callstack == exemplar_callstack)
            l.debug("...%d with unique callstack #%d", len(simgr.merge_tmp), num_unique)
            if len(simgr.merge_tmp) > 1:
                simgr = simgr.merge(stash='merge_tmp')
            simgr = simgr.move('merge_tmp', stash)

        return simgr
