from . import ExplorationTechnique

class LengthLimiter(ExplorationTechnique):
    """
    限定路径长度的搜索技术
    """

    # 初始化函数,初始化路径的最大长度
    def __init__(self, max_length, drop=False):
        super(LengthLimiter, self).__init__()
        self._max_length = max_length
        self._drop = drop

    # 过滤函数,给路径长度大于给定最大长度的state做标记,
    # 表明此state会从active stash中移除
    def _filter(self, s):
        return s.history.block_count > self._max_length

    # 重写ExplorationTechnique中的step函数,默认是对active stash中的states的操作
    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        # 将符合上面过滤函数要求的state从active中移到_DROP stash或者cut stash中
        # 如果给定drop为True就是移到_DROP中,为False就是移到cut中
        simgr.move('active', '_DROP' if self._drop else 'cut', self._filter)
        return simgr
