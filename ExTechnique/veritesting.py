from . import ExplorationTechnique

from ..sim_options import EFFICIENT_STATE_MERGING

class Veritesting(ExplorationTechnique):
    """
    启用veritesting搜索技术。  CMU的论文[1]中描述了这种技术，
    它试图通过执行智能合并来解决循环中状态爆炸的问题。

    [1] https://users.ece.cmu.edu/~aavgerin/papers/veritesting-icse-2014.pdf
    """

    # 初始化函数的一些必需的参数
    def __init__(self, **options):
        super(Veritesting, self).__init__()
        self.options = options

    # 重写ExplorationTechnique中的step_state函数
    def step_state(self, simgr, state, successor_func=None, **kwargs):

        # 首先保证EFFICIENT_STATE_MERGING这个状态选项是开启的,不存在就添加进去
        if EFFICIENT_STATE_MERGING not in state.options:
            state.options.add(EFFICIENT_STATE_MERGING)

        # 执行veritesting分析
        vt = self.project.analyses.Veritesting(state, **self.options)
        # 如果执行成功并且得到执行后的SimulationManager
        if vt.result and vt.final_manager:
            # 将执行后得到的simgr中的deviated stash和successful stash中的states
            # 都移到active stash中,得到一个新的simgr
            simgr2 = vt.final_manager
            simgr2.stash(from_stash='deviated', to_stash='active')
            simgr2.stash(from_stash='successful', to_stash='active')

            # 返回新的simgr中的stashes的信息
            return {
                    'active': simgr2.active,
                    'unconstrained': simgr2.stashes.get('unconstrained', []),
                    'unsat': simgr2.stashes.get('unsat', []),
                    'pruned': simgr2.stashes.get('pruned', []),
                    'errored': simgr2.errored,
                    }

        return simgr.step_state(state, successor_func=successor_func, **kwargs)
