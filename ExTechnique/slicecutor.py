from ..errors import AngrExitError
from . import ExplorationTechnique

import logging
l = logging.getLogger(name=__name__)


class Slicecutor(ExplorationTechnique):
    """
    Slicecutor是一种执行提供的代码片段的搜索技术
    """

    def __init__(self, annotated_cfg, force_taking_exit=False):
        """
        初始化函数参数,annotated_cfg是必需的.
        annotated_cfg:      用来提供代码片段
        force_taking_exit:  如果你想基于给定代码片段产生后继的话就设置未True
        """
        super(Slicecutor, self).__init__()

        self._annotated_cfg = annotated_cfg
        self._force_taking_exit = force_taking_exit

    # 重写ExplorationTechnique中的setup函数,初始化simgr
    def setup(self, simgr):
        # 初始化cut和mysteries两个stash为空
        for stash in ('cut', 'mysteries'):
            simgr.populate(stash, [])

    # 重写ExplorationTechnique中的filter函数,此处还是遵循原始的分类方法
    def filter(self, simgr, state, **kwargs):
        l.debug("Checking state %s for filtering...", state)
        return simgr.filter(state, **kwargs)

    # 重写ExplorationTechnique中的step_state函数,确定状态的后继存储在哪个stash中
    def step_state(self, simgr, state, **kwargs):
        l.debug("%s ticking state %s at address %#x.", self, state, state.addr)
        stashes = simgr.step_state(state, **kwargs)

        new_active = []
        new_cut = []
        new_mystery = []

        # 默认情况下,simgr在None stash中返回新的active states
        flat_successors = stashes.get(None, None)
        if flat_successors is None:
            # 将active中的states给到flat_successors中
            flat_successors = stashes.pop('active', [])

        # 对flat_successors中的元素进行处理
        for successor in flat_successors:
            l.debug("... checking exit to %#x from %#x.", successor.addr, state.addr)

            try:
                # 判断state的后继是否是successor
                taken = self._annotated_cfg.should_take_exit(state.addr, successor.addr)
            except AngrExitError: # TODO: which exception?
                l.debug("... annotated CFG did not know about it!")
                # 出现异常则将successor添加到new_mystery列表中
                new_mystery.append(successor)
            else:
                if taken:
                    l.debug("... taking the exit.")
                    # 没有出现异常且taken为True,则将successor添加到new_active列表中
                    new_active.append(successor)
                else:
                    l.debug("... not taking the exit.")
                    # 没有出现异常且taken为False,则将successor添加到new_cut列表中
                    new_cut.append(successor)

        # 将unconstrained stash中的states提取到unconstrained_successors中
        unconstrained_successors = stashes.get('unconstrained', [])
        # 如果new_active为空,unconstrained_successors不为空并且_force_taking_exit为True
        if not new_active and unconstrained_successors and self._force_taking_exit:
            stashes['unconstrained'] = []
            # 没有可行的state,我们要根据给定的代码片段产生successor,并将successor添加到new_active列表中
            if len(unconstrained_successors) != 1:
                raise Exception("This should absolutely never happen, what?")
            for target in self._annotated_cfg.get_targets(state.addr):
                successor = unconstrained_successors[0].copy()
                successor.regs._ip = target
                new_active.append(successor)
            l.debug('Got unconstrained: %d new states are created based on AnnotatedCFG.', len(new_active))

        stashes[None] = new_active
        stashes['mystery'] = new_mystery
        stashes['cut'] = new_cut
        return stashes

    # 重写successors方法,返回一个SimSuccessors对象
    def successors(self, simgr, state, **kwargs):
        # 改变了函数的kwargs,用来获取代码片段的successor
        kwargs['whitelist'] = self._annotated_cfg.get_whitelisted_statements(state.addr)
        kwargs['last_stmt'] = self._annotated_cfg.get_last_statement_index(state.addr)
        return simgr.successors(state, **kwargs)
