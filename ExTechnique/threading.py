# pylint: disable=cell-var-from-loop
import concurrent.futures

from . import ExplorationTechnique

class Threading(ExplorationTechnique):
    """
    启用多线程的搜索技术。

    这仅在z3内部花费大量时间进行约束求解的路径中有用。
    这是由于python的GIL所致，该GIL表示一次只能执行一个线程。
    """

    # 初始化函数参数,默认初始化线程个数为8
    def __init__(self, threads=8):
        super(Threading, self).__init__()
        self.threads = threads
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)

    # 重写ExplorationTechnique中的step函数,默认是对active stash的操作
    def step(self, simgr, stash='active', **kwargs):
        counts = [0]*self.threads
        def counts_of(i):
            out = counts[i]
            counts[i] = out + 1
            return out

        tasks = {}
        for x in range(self.threads):
            # 使用带有对象标识的列表构造新的simgr
            # 将第x个线程移动到唯一的线程本地列表中
            # 这意味着线程不会破坏彼此的hooks但仍可以协商共享资源

            # 使用copy()函数构造一个新的tsimgr
            tsimgr = simgr.copy(stashes=dict(simgr.stashes))
            # 使tsimgr中的threadlocal stash为空
            tsimgr.stashes['threadlocal'] = []
            # 将第x个线程中的active stash中的states移动到threadlocal stash中
            tsimgr.move(stash, 'threadlocal', lambda path: counts_of(x) % self.threads == x)
            # 对tsimgr中的threadlocal中的states进行step操作
            tasks[self.executor.submit(tsimgr.step, stash='threadlocal', **kwargs)] = tsimgr

        for f in concurrent.futures.as_completed(tasks):
            # 将对threadlocal中的states进行了step操作后得到的states填充到原simgr中的active中
            simgr.populate(stash, tasks[f].threadlocal)

        return simgr
