from . import ExplorationTechnique


class TechniqueBuilder(ExplorationTechnique):
    """
    该元技术可用于挂钩几种simulation manager方法，
    而无需实际创建新的探索技术，例如：

    class SomeComplexAnalysis(Analysis):

        def do_something():
            simgr = self.project.factory.simulation_manager()
            simgr.use_tech(ProxyTechnique(step_state=self._step_state))
            simgr.run()

        def _step_state(self, state):
            # Do stuff!
            pass

    在上面的示例中，_step_state方法可以访问隐藏在分析实例中的所有必要内容，
    而无需将该实例传递给单次使用的探索技术。
    """

    # 初始化函数必需参数
    def __init__(self, setup=None, step_state=None, step=None, successors=None,
                 filter=None, selector=None, complete=None):
        super(TechniqueBuilder, self).__init__()
        self.setup = _its_a_func(setup) or super(TechniqueBuilder, self).setup
        self.step_state = _its_a_func(step_state) or super(TechniqueBuilder, self).step_state
        self.step = _its_a_func(step) or super(TechniqueBuilder, self).step
        self.filter = _its_a_func(filter) or super(TechniqueBuilder, self).filter
        self.successors = _its_a_func(successors) or super(TechniqueBuilder, self).successors
        self.selector = _its_a_func(selector) or super(TechniqueBuilder, self).selector
        self.complete = _its_a_func(complete) or super(TechniqueBuilder, self).complete


def _its_a_func(func):
    """

    防止目标函数没有设置“ im_func” 属性。

    """
    if func is not None:
        func.im_func = True
    return func
