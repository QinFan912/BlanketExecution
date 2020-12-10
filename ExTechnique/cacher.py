import os
import string
import hashlib
import tempfile
import logging

from . import ExplorationTechnique
from .common import condition_to_lambda

l = logging.getLogger(name=__name__)


class Cacher(ExplorationTechnique):
    """
    一种在符号执行期间缓存状态的探索技术。
    请勿使用-这仅是出于存档目的
    """

    def __init__(self, when=None, dump_cache=True, load_cache=True, container=None,
                 lookup=None, dump_func=None, load_func=None):
        """
        初始化函数参数:
        dump_cache: 是否将数据转储到缓存
        load_cache: 是否从缓存加载数据
        container:  数据容器
        when:       如果提供的话，应为采用SimulationManager并返回布尔值或要缓存的状态的地址的函数。
        lookup:     如果缓存命中，则返回True，否则返回False的函数。
        dump_func:  如果提供的话，应该是定义Cacher如何缓存SimulationManager的函数。 默认为缓存active stash中的state。
        load_func:  如果提供的话，应为定义Cacher如何取消对SimulationManager的缓存的函数。 默认为取消缓存要步进的stash。
        """
        super(Cacher, self).__init__()
        self._dump_cond, _ = condition_to_lambda(when)
        self._dump_cache = dump_cache
        self._load_cache = load_cache
        self._cache_lookup = self._lookup if lookup is None else lookup
        self._dump_func = self._dump_stash if dump_func is None else dump_func
        self._load_func = self._load_stash if load_func is None else load_funcno

        self.container = container
        self.container_pickle_str = isinstance(container, str) and not all(c in string.printable for c in container)

    # 重写ExplorationTechnique中的setup函数
    def setup(self, simgr):
        # binary表示二进制文件的名字
        binary = simgr._project.filename
        # binhash是binary经过md5加密后的16进制表示
        binhash = hashlib.md5(open(binary).read()).hexdigest()

        if self.container is None:
            # 创建一个临时目录来保存缓存文件
            tmp_directory = tempfile.mkdtemp(prefix="angr_cacher_container")
            # 创建缓存文件(容器)
            self.container = os.path.join(tmp_directory, "%s-%s.cache" % (os.path.basename(binary), binhash))

        # 如果容器是文件名,确保字典中的keys值是name,binhash和addr
        elif isinstance(self.container, str) and not self.container_pickle_str:
            try:
                self.container = self.container % {'name': os.path.basename(binary), 'binhash': binhash,
                                                   'addr': '%(addr)s'}
            except KeyError:
                l.error("Only the following cache keys are accepted: 'name', 'binhash' and 'addr'.")
                raise

        # 如果_load_cache为True并且constainer是str或者file类型的,就要从缓存加载数据
        if self._load_cache and self._cache_lookup():
            l.warning("Uncaching from %s...", self.container)
            self._load_func(self.container, simgr)

        self.project = simgr._project

    # 重写ExplorationTechnique中的step函数,默认是对active stash的操作
    def step(self, simgr, stash='active', **kwargs):
        # 如果active中的任一state满足条件,就进行缓存
        for s in simgr.stashes[stash]:
            if self._dump_cache and self._dump_cond(s):
                if isinstance(self.container, str):
                    self.container = self.container % {'addr': hex(s.addr)[:-1]}

                if self._cache_lookup():
                    continue

                l.warning("Caching to %s...", self.container)

                self._dump_func(self.container, simgr, stash)

        return simgr.step(stash=stash, **kwargs)

    # 判断container是否是str或者file类型
    def _lookup(self):
        # 如果container是str类型,返回True
        if isinstance(self.container, str):
            if self.container_pickle_str:
                return True

            elif os.path.exists(self.container):
                return True

            else:
                return False

        # 如果container是file类型,返回True
        elif isinstance(self.container, file):
            return True

        # 否则,警告并返回False
        else:
            l.warning("Default Cacher cannot recognize containers of type other than 'str' and 'file'.")
            return False

    @staticmethod
    # 当没有给出load_func时,令_load_func=_load_stash,表示从缓存加载数据的函数
    def _load_stash(container, simgr):
        project = simgr._project
        cached_project = project.load_function(container)

        if cached_project is not None:
            cached_project.analyses = project.analyses
            cached_project.store_function = project.store_function
            cached_project.load_function = project.load_function

            stash = cached_project.storage['cached_states']
            for s in stash:
                s.project = cached_project

            # 将cached_states中的states加载一份到active stash中
            simgr.stashes['active'] = stash
            cached_project.storage = None

            simgr._project = cached_project

        else:
            l.error("Something went wrong during Project unpickling...")

    @staticmethod
    # 当没有给出dump_func时,令_dunp_func=_dump_stash,表示将数据转储到缓存的函数
    def _dump_stash(container, simgr, stash):
        for s in simgr.stashes[stash]:
            s.project = None
            s.history.trim()

        project = simgr._project
        project.storage['cached_states'] = simgr.stashes[stash]
        project.store_function(container)

        for s in simgr.stashes[stash]:
            s.project = project
