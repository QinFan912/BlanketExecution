
import math
from collections import defaultdict
import logging

from ..engines.successors import SimSuccessors
from . import ExplorationTechnique

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)


class Bucketizer(ExplorationTechnique):
    """
    循环存储：从n个可能的路径中选择log（n）个路径，然后隐藏（或丢弃）其他所有内容。
    """

    # 初始化函数
    def __init__(self):

        super().__init__()

    # 重写ExplorationTechnique中的ssuccessors函数
    def successors(self, simgr, state, **kwargs):

        # 先执行获取给定state的后继状态
        successors = super().successors(simgr, state, **kwargs)  # type: SimSuccessors

        # 如果有多个后继状态，我们会尝试摆脱那些我们不希望的后继状态

        # 如果后继状态<=1,直接返回得到的后继状态
        if len(successors.successors) <= 1:
            return successors

        new_successors = [ ]

        # 将符合要求的succ添加到new_successors列表中
        for succ in successors.successors:
            if succ.history.jumpkind != 'Ijk_Boring':
                new_successors.append(succ)
                continue
            # transition = (succ.callstack.func_addr, succ.history.addr, succ.addr)
            transition = succ.addr
            self._record_transition(succ, transition)

            if self._accept_transition(succ, transition):
                new_successors.append(succ)

        # 比较new_successors列表与后继状态列表的个数,
        # 不相等,给出从多少个后继状态中移除了多少个状态
        if len(new_successors) != len(successors.successors):
            _l.debug("Bucketizer: Dropped %d states out of %d.",
                     len(successors.successors) - len(new_successors),
                     len(successors.successors))

        # 将new_successors列表中的states作为后级状态并输出
        successors.successors = new_successors
        return successors

    # 得到transition字典的函数
    def _get_transition_dict(self, state):
        """

        :param SimState state:
        :return:
        """

        try:
            t = state.globals['transition']
        except KeyError:
            t = defaultdict(int)
            state.globals['transition'] = t
        return t

    # 给transition字典中每个transition加一计数的函数
    def _record_transition(self, state, transition):
        """

        :param SimState state:
        :param tuple transition:
        :return:
        """

        t = self._get_transition_dict(state).copy()
        t[transition] += 1

        state.globals['transition'] = t

    # 判断transition字典中每个transition是否被接受的函数
    def _accept_transition(self, state, transition):
        """

        :param SimState state:
        :param tuple transition:
        :return:
        """

        t = self._get_transition_dict(state)

        # 当transition的计数为0或者log2(transition当前计数)的结果为整数时,返回True
        if t[transition] == 0:
            _l.error("Impossible: Transition %s has 0 occurrences.", transition)
            return True

        n = math.log2(t[transition])
        if n.is_integer():
            return True
        return False
