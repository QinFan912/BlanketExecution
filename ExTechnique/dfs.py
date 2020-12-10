from . import ExplorationTechnique
import random

class DFS(ExplorationTechnique):
    """
    深度优先搜索。

     一次只能保持一条路径处于活动状态，任何其他路径将被隐藏在“deferred”存储区中。
     当我们用尽active stash 中的states时,我们会从deferred stash中选择最长的路径那个state继续执行.
    """

    # 初始化函数参数
    def __init__(self, deferred_stash='deferred'):
        super(DFS, self).__init__()
        self._random = random.Random()
        self._random.seed(10)
        self.deferred_stash = deferred_stash

    # 重写ExplorationTechnique中的setup函数,初始化simgr
    def setup(self, simgr):
        # 令deferred stash为空
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []

    # 重写ExplorationTechnique中的step函数,默认是对active stash中的states的操作
    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        # 如果active stash中的state个数大于1,就将active stash中的state移到deferred stash中,
        # 只保留一个state在active stash中
        if len(simgr.stashes[stash]) > 1:
            self._random.shuffle(simgr.stashes[stash])
            simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=1)

        # 如果active stash中的state个数等于0
        if len(simgr.stashes[stash]) == 0:
            # 如果此时deferred stash中的state个数也等于0,返回simgr并退出
            if len(simgr.stashes[self.deferred_stash]) == 0:
                return simgr
            # 否则,从deferred stash中取出一个state添加到active stash中
            simgr.stashes[stash].append(simgr.stashes[self.deferred_stash].pop())

        return simgr
