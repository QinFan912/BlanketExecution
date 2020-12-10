import random
from collections import defaultdict

from . import ExplorationTechnique

class StochasticSearch(ExplorationTechnique):
    """
    随机搜索技术。

    一次只会保持一条路径处于活动状态，而其他路径将被丢弃。
    在每次执行之前，权重被随机分配给每个state。
    这些权重形成概率分布，用于确定拆分后仍保留哪个状态。
    当我们用完活动路径时，我们将从开始状态重新开始。
    """

    # 初始化必要参数
    def __init__(self, start_state, restart_prob=0.0001):
        """
        :param start_state:  探索的初始状态。
        :param restart_prob: 随机重新开始搜索的概率（默认为0.0001）。
        """
        super(StochasticSearch, self).__init__()
        self.start_state = start_state
        self.restart_prob = restart_prob
        self._random = random.Random()
        self._random.seed(42)
        self.affinity = defaultdict(self._random.random)

    # 重写ExplorationTechnique中的step函数,默认是对active stash中的states的操作
    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        # 当active stash为空或者随机数小于重新开始搜索的概率,
        # 就从初始状态开始执行,并清空保存权重信息的字典
        if not simgr.stashes[stash] or self._random.random() < self.restart_prob:
            simgr.stashes[stash] = [self.start_state]
            self.affinity.clear()

        # 如果active中的states个数大于等于2
        if len(simgr.stashes[stash]) >= 2:
            # 通过权重提取state的方法
            def weighted_pick(states):
                # states的个数大于等于2时正常进行
                assert len(states) >= 2
                # 对states中的每个state的地址给一个随机数作为它的权重,并求总权重值
                total_weight = sum((self.affinity[s.addr] for s in states))
                # 从0到total_weight中随机选取一个数
                selected = self._random.uniform(0, total_weight)
                i = 0
                # 对states中的每个state求权重,并与selected这个随机数比较,
                # 取出权重小于等于selected数的state,并且selected = selected - weight(取出的state的权重)
                for i, state in enumerate(states):
                    weight = self.affinity[state.addr]
                    if selected < weight:
                        break
                    else:
                        selected -= weight
                picked = states[i]
                return picked

            # 从active stash的states中按上述随机提取的方法获取一个state,作为active中的唯一一个state
            # 这样就会只保持一条路径处于活动状态
            simgr.stashes[stash] = [weighted_pick(simgr.stashes[stash])]

        return simgr
