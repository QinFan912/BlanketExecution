import logging
from collections import defaultdict
import angr
import networkx

import claripy

from ..sim_type import SimType, SimTypePointer, SimTypeChar, SimTypeString, SimTypeReg
from ..calling_conventions import DEFAULT_CC
from ..knowledge_base import KnowledgeBase
from ..errors import AngrDirectorError
from . import ExplorationTechnique


class Director(ExplorationTechnique):
    """
    定向符号执行的探索技术。

    在符号执行过程中建立并完善了控制流程图（使用CFGEmulated）。 每次执行到达CFG外部的块时，CFG恢复将在该状态触发，并具有最大恢复深度（默认为100）。
    如果在状态步进过程中看到一个尚未在控制流程图中的基本块，则返回到控制流程图的恢复过程中，并向前“窥视”更多块。

    步进模拟管理器时，所有状态都分为两类：

    -可能会在窥视深度之内到达目的地。 这些状态是优先的。

    -不会在窥视深度之内到达目的地。 这些状态被取消优先级,即不是优先的。 但是，也有很小的机会探索这些状态，以防止过度拟合。
    """

    # 初始化函数需要的一些基本参数
    def __init__(self, peek_blocks=100, peek_functions=5, goals=None, cfg_keep_states=False,
                 goal_satisfied_callback=None, num_fallback_states=5):

        super(Director, self).__init__()

        self._peek_blocks = peek_blocks
        self._peek_functions = peek_functions
        self._goals = goals if goals is not None else []
        self._cfg_keep_states = cfg_keep_states
        self._goal_satisfied_callback = goal_satisfied_callback
        self._num_fallback_states = num_fallback_states

        self._cfg = None
        self._cfg_kb = None

    # 重写ExplorationTechnique中的step函数,默认对active stash中的states的操作
    def step(self, simgr, stash='active', **kwargs):

        # 确保所有的当前基本块都在CFG中
        self._peek_forward(simgr)

        # 在simulation manager中对所有状态进行分类
        self._categorize_states(simgr)

        if not simgr.active:
            # active stash为空,即我们现有的状态都无法确保达到目标
            # 此时就从deprioritized stash中提取states到active stash中
            self._load_fallback_states(simgr)

        if simgr.active:
            # active stash不为空,对其进行step操作
            simgr = simgr.step(stash=stash)

        if not simgr.active:
            self._load_fallback_states(simgr)

        return simgr

    # 添加一个目标的函数
    def add_goal(self, goal):
        # 让goals列表添加一个goal
        self._goals.append(goal)

    def _peek_forward(self, simgr):
        """
        确保每个状态下的所有当前基本块都显示在CFG中。 对于不在CFG中的块，以最大基本块深度为100从它们(即不在CFG中的基本块)开始进行CFG恢复。

        :param simgr:
        :return:
        """
        if self._cfg is None:
            # 如果cfg为空,从active开始使用CFGEmulated创建cfg
            starts = list(simgr.active)
            self._cfg_kb = KnowledgeBase(self.project)

            self._cfg = self.project.analyses.CFGEmulated(kb=self._cfg_kb, starts=starts, max_steps=self._peek_blocks,
                                                          keep_state=self._cfg_keep_states
                                                          )
        else:
            # 如果cfg不为空,从active开始使用resume进行cfg恢复
            starts = list(simgr.active)

            self._cfg.resume(starts=starts, max_steps=self._peek_blocks)

    def _load_fallback_states(self, pg):
        """
        将从“deprioritized”stash中提取最后N个已取消优先处理的状态，并将其置于“active”stash中。
           N由“ num_fallback_states”控制。

        :param SimulationManager pg: The simulation manager.
        :return: None
        """

        # 收回一些低优先级的state,并添加到active stash中
        l.debug("No more active states. Load some deprioritized states to 'active' stash.")
        if 'deprioritized' in pg.stashes and pg.deprioritized:
            pg.active.extend(pg.deprioritized[-self._num_fallback_states:])
            pg.stashes['deprioritized'] = pg.deprioritized[: -self._num_fallback_states]

    def _categorize_states(self, simgr):
        """
        将所有状态分为两个不同的组：在窥视深度之内到达目的地的，和在窥视深度之内不能到达目的地的。

        :param SimulationManager simgr:    The simulation manager that contains states. All active states
                                (state belonging to "active" stash)
                                are subjected to categorization.
        :return:                The categorized simulation manager.
        :rtype:                 angr.SimulationManager
        """
        past_active_states = len(simgr.active)
        # past_deprioritized_states = len(simgr.deprioritized)

        # 对goals中的每个goal,检查active中的每个state能否到达该goal
        for goal in self._goals:
            for p in simgr.active:
                if self._check_goals(goal, p):
                    if self._goal_satisfied_callback is not None:
                        self._goal_satisfied_callback(goal, p, simgr)

        # 将不能在给定深度内到达目标的states从active中移到deprioritized stash中
        simgr.stash(
            filter_func=lambda p: all(not goal.check(self._cfg, p, peek_blocks=self._peek_blocks) for goal in
                                      self._goals
                                      ),
            from_stash='active',
            to_stash='deprioritized',
        )

        if simgr.active:
            # TODO: pick some states from depriorized stash to active stash to avoid overfitting
            pass

        active_states = len(simgr.active)
        # deprioritized_states = len(simgr.deprioritized)

        l.debug('%d/%d active states are deprioritized.', past_active_states - active_states, past_active_states)

        return simgr

    def _check_goals(self, goal, state):  # pylint:disable=no-self-use
        """
        检查状态是否满足目标

        :param BaseGoal goal: The goal to check against.
        :param angr.SimState state: The state to check.
        :return: True if the state satisfies the goal currently, False otherwise.
        :rtype: bool
        """

        return goal.check_state(state)
