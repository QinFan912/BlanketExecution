from difflib import SequenceMatcher
from collections import Counter

from . import ExplorationTechnique

class UniqueSearch(ExplorationTechnique):
    """
    唯一搜索方法。

    一次只会保持一条路径处于活动状态，而其他路径将被推迟。
       探索的状态取决于它相对于其他延期状态的唯一性。
       路径的唯一性取决于它与其他（延迟）路径之间的平均相似度。
       相似度是根据所提供的“ similarity_func”来计算的，默认情况下为：历史路径中状态地址计数之间的（L2）距离。
    """

    # 初始化函数的一些必需的参数
    def __init__(self, similarity_func=None, deferred_stash='deferred'):
        """
        :param similarity_func: 如何计算两个状态之间的相似度。
        :param deferred_stash:  存放延迟状态的位置。
        """
        super(UniqueSearch, self).__init__()
        self.similarity_func = similarity_func or UniqueSearch.similarity
        self.deferred_stash = deferred_stash
        self.uniqueness = dict()
        self.num_deadended = 0

    # 重写ExplorationTechnique中的setup函数,初始化存放延迟states的deferred_stash为空
    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []

    # 重写ExplorationTechnique中的step函数,默认是对active stash的操作
    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        # 将deferred_stash列表中的states赋值给old_states
        old_states = simgr.stashes[self.deferred_stash][:]
        # 将active stash列表中的states赋值给new_states
        new_states = simgr.stashes[stash][:]
        # 将active stash中的states移到deferred_stash中
        simgr.move(from_stash=stash, to_stash=self.deferred_stash)

        def update_average(state, new, mem=1.0):
            """
            param state: 要更新平均值的状态。
            param new:   将累加到平均值中的新值。
            param mem:   内存参数用来确定如何加权以前的平均值。
            """
            prev, size = self.uniqueness[state]
            new_average = float(prev * (size ** mem) + new) / ((size ** mem) + 1)
            self.uniqueness[state] = new_average, size + 1

        # 对于new_states中的state,即原来的active stash中的state
        for state_a in new_states:
            self.uniqueness[state_a] = 0, 0
            for state_b in old_states:
                # 更新new_states和old_states中的状态之间的相似度平均值
                # 先计算两状态之间的相似性
                similarity = self.similarity_func(state_a, state_b)
                # 然后更新两个状态的平均值
                update_average(state_a, similarity)
                update_average(state_b, similarity)
            for state_b in (s for s in new_states if s is not state_a):
                # 更新new_states中状态之间的相似度平均值
                similarity = self.similarity_func(state_a, state_b)
                update_average(state_a, similarity)

        for state_a in simgr.stashes[self.deferred_stash]:
            for state_b in simgr.deadended[self.num_deadended:]:
                # 更新所有状态与新的失效状态之间的相似度平均值
                similarity = self.similarity_func(state_a, state_b)
                update_average(state_a, similarity)
        self.num_deadended = len(simgr.deadended)

        if self.uniqueness:
            # 从uniqueness字典中找到相似性平均数最小的state,然后删除
            unique_state = min(self.uniqueness.items(), key=lambda e: e[1])[0]
            del self.uniqueness[unique_state]

            # 将上面找到的相似性最小即具有唯一性的state从deferred_stash中移到active stash中
            simgr.move(from_stash=self.deferred_stash, to_stash=stash,
                       filter_func=lambda s: s is unique_state)

        return simgr

    @staticmethod
    def similarity(state_a, state_b):
        """
        计算两个state之间的相似性:
        历史路径中状态地址计数之间的（L2）距离。
        :param state_a: 比较的第一个状态
        :param state_b: 比较的第二个状态
        """
        # 计算state执行的基本块地址的出现次数
        count_a = Counter(state_a.history.bbl_addrs)
        count_b = Counter(state_b.history.bbl_addrs)
        # 计算距离
        normal_distance = sum((count_a.get(addr, 0) - count_b.get(addr, 0)) ** 2
                              for addr in set(list(count_a.keys()) + list(count_b.keys()))) ** 0.5
        return 1.0 / (1 + normal_distance)

    @staticmethod
    def sequence_matcher_similarity(state_a, state_b):
        """
        路径历史记录中状态地址之间的`difflib.SequenceMatcher`比率。
        :param state_a: 比较的第一个状态
        :param state_b: 比较的第二个状态
        """
        # 将state执行的基本块地址序列设为元组
        addrs_a = tuple(state_a.history.bbl_addrs)
        addrs_b = tuple(state_b.history.bbl_addrs)
        # 计算上面两个元组中地址一样的比率
        return SequenceMatcher(a=addrs_a, b=addrs_b).ratio()
