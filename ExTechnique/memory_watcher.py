from . import ExplorationTechnique
import psutil

class MemoryWatcher(ExplorationTechnique):
    """
    内存观察器

    参数:
        min_memory:停止执行之前的最小可用内存量（MB）（默认值：95％的内存使用）

        memory_stash:用来隐藏状态的stash（默认值：“ lowmem”）

    在每个步骤中，请注意系统上还有多少内存, 如果低于给定的阈值，则隐藏状态以有效地停止执行。
    """

    # 初始化函数参数,主要是初始化最小内存min_memory和要用来隐藏状态的memory_stash
    def __init__(self, min_memory=512, memory_stash='lowmem'):
        super(MemoryWatcher, self).__init__()

        # 如果提供了min_memory则使用提供的值,否则取总内存的5%
        if min_memory is not None:
            self.min_memory = 1024*1024*min_memory

        else:
            self.min_memory = int(psutil.virtual_memory().total * 0.05)

        self.memory_stash = memory_stash

    # 重写ExplorationTechnique中的setup函数
    def setup(self, simgr):
        # 初始化memory_stash为空
        if self.memory_stash not in simgr.stashes:
            simgr.stashes[self.memory_stash] = []

    # 重写ExplorationTechnique中的step函数,默认是对active stash中的states的操作
    def step(self, simgr, stash='active', **kwargs):

        # 当可用内存不大于min_memory时,将active stash中的states都移到memory_stash中
        if psutil.virtual_memory().available <= self.min_memory:
            simgr.move(from_stash='active', to_stash=self.memory_stash)

        # 否则的话,继续对active stash中的states进行step()操作
        else:
            simgr = simgr.step(stash=stash, **kwargs)

        return simgr
