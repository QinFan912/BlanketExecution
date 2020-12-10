
import logging
from .common import condition_to_lambda
from . import ExplorationTechnique

l = logging.getLogger("angr.exploration_techniques.symbion")
# l.setLevel(logging.DEBUG)


class Symbion(ExplorationTechnique):
    """
    Symbion探索技术使用可用的SimEngineConcrete来步进SimState。

    :param find: 地址或我们要到达的地址列表，这些地址将使用用户在SimEngineConcrete内部
                 提供的ConcreteTarget接口被转换为具体过程内部的断点。

    :param memory_concretize: 将要写入具体过程存储器中的元组（地址，符号变量）列表。

    :param register_concretize: 将要编写的元组列表（reg_name，符号变量）

    :param timeout: 我们应该等待多久,具体目标才能达到断点

    """

    # 初始化函数,初始化一些必需的参数
    def __init__(self, find=None, memory_concretize=None, register_concretize=None, timeout=0, find_stash='found'):
        super(Symbion, self).__init__()
        # 需要保留原始地址列表
        self.breakpoints = find
        self.find = condition_to_lambda(find)
        self.memory_concretize = memory_concretize
        self.register_concretize = register_concretize
        self.find_stash = find_stash
        self.timeout = timeout

    # 重写ExplorationTechnique中的setup函数,初始化simgr
    def setup(self, simgr):
        # 在这个setup过程中,添加'found'stash到simgr中,并初始化为空列表
        simgr.stashes[self.find_stash] = []

    # 重写ExplorationTechnique中的step函数,默认是对active stash中的states的操作
    def step(self, simgr, stash='active', **kwargs):
        # 首先要保证active stash不为空
        if not len(simgr.stashes[stash]):
            l.warning("No stashes to step, aborting.")
            return None

        # 检查active中是否仅包含一个SimState，
        # 如果不是，则警告用户该存储区中仅第一个状态可以进入SimEngineConcrete。
        # 这是因为目前我们仅支持一个具体的执行
        if len(simgr.stashes[stash]) > 1:
            l.warning("You are trying to use the Symbion exploration technique on multiple state, "
                      "this is not supported now.")

        return simgr.step(stash=stash, **kwargs)

    # 重写ExplorationTechnique中的step_state函数
    def step_state(self, simgr, *args, **kwargs): #pylint:disable=arguments-differ
        state = args[0]
        # 对当前唯一的state进行successors操作,得到该state的后继状态,
        # 将得到的后继状态添加到found stash中
        ss = self.successors(state=state, simgr=simgr, engine=self.project.factory.concrete_engine,
                                          extra_stop_points=self.breakpoints,
                                          memory_concretize=self.memory_concretize,
                                          register_concretize=self.register_concretize,
                                          timeout=self.timeout)

        new_state = ss.successors

        if new_state[0].timeout:
            return {'timeout': new_state}

        return {'found': new_state}

    # 重写ExplorationTechnique中的complete函数
    def complete(self, simgr):
        # 如果我们在具体执行中至少到达了一个断点，我们就完成了此次操作
        return len(simgr.stashes[self.find_stash]) >= 1
