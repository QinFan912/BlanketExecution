# pylint:disable=no-member
import logging
import datetime

try:
    import sqlalchemy
    from sqlalchemy import Column, Integer, String, Boolean, DateTime, create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.exc import OperationalError

    Base = declarative_base()


    class PickledState(Base):
        __tablename__ = "pickled_states"

        id = Column(String, primary_key=True)
        priority = Column(Integer)
        taken = Column(Boolean, default=False)
        stash = Column(String, default="")
        timestamp = Column(DateTime, default=datetime.datetime.utcnow)

except ImportError:
    sqlalchemy = None

l = logging.getLogger(name=__name__)

from . import ExplorationTechnique


class Spiller(ExplorationTechnique):
    """
    自动溢出状态。 它可以将状态溢出到其他存储区，或将其溢出到磁盘，
    或者先进行前者处理，然后再（在有足够的状态下）进行后者处理。
    """

    # 初始化函数,初始化一些必需参数
    def __init__(
            self,
            src_stash="active", min=5, max=10,  # pylint:disable=redefined-builtin
            staging_stash="spill_stage", staging_min=10, staging_max=20,
            pickle_callback=None, unpickle_callback=None, post_pickle_callback=None,
            priority_key=None, vault=None, states_collection=None,
    ):
        """
        初始化溢出器。

        @param max:不需泄漏的state数
        @param src_stash: 从哪个stash中溢出状态（默认值：active）
        @param staging_stash: 将溢出的状态存储在哪个stash中（默认值：“ spill_stage”）
        @param staging_max: 在state泄漏到磁盘之前，可以处在spill_stage　stash中的最大状态数（默认值：无。如果设置了staging_stash，则意味着不受限制，并且不会使用磁盘）。
        @param priority_key: 返回一个状态的数字优先级的函数（MAX INT是最低优先级）。 默认情况下，将使用self.state_priority，该优先级按对象ID优先。
        @param vault: angr.Vault对象，用于处理状态的存储和加载。 如果未提供，将使用一个临时文件创建一个angr.vaults.VaultShelf。
        """
        super(Spiller, self).__init__()
        self.max = max
        self.min = min
        self.src_stash = src_stash
        self.staging_stash = staging_stash
        self.staging_max = staging_max
        self.staging_min = staging_min

        self.priority_key = priority_key
        self.unpickle_callback = unpickle_callback
        self.pickle_callback = pickle_callback
        self.post_pickle_callback = post_pickle_callback

        self._pickled_states = PickledStatesList() if states_collection is None else states_collection
        self._ever_pickled = 0
        self._ever_unpickled = 0
        self._vault = vaults.VaultShelf() if vault is None else vault

    # 从磁盘读取states的函数
    def _unpickle(self, n):
        self._pickled_states.sort()
        unpickled = [(sid, self._load_state(sid)) for _, sid in self._pickled_states.pop_n(n)]
        self._ever_unpickled += len(unpickled)
        if self.unpickle_callback:
            for sid, u in unpickled:
                self.unpickle_callback(sid, u)
        return [u for _, u in unpickled]

    # 通过id来获取state的优先级的函数
    def _get_priority(self, state):
        return (self.priority_key or self.state_priority)(state)

    # 将states存储到磁盘中的函数
    def _pickle(self, states):
        if self.pickle_callback:
            for s in states:
                self.pickle_callback(s)
        self._ever_pickled += len(states)
        for state in states:
            try:
                state_oid = self._store_state(state)
            except RecursionError:
                l.warning("Couldn't store the state because of a recursion error. This is most likely to be pickle's "
                          "fault. You may try to increase the recursion limit using sys.setrecursionlimit().")
                continue
            prio = self._get_priority(state)
            if self.post_pickle_callback:
                self.post_pickle_callback(state, prio, state_oid)
            self._pickled_states.add(prio, state_oid)

    # 存储state的函数
    def _store_state(self, state):
        return self._vault.store(state)

    # 读取state的函数
    def _load_state(self, sid):
        return self._vault.load(sid)

    # 重写ExplorationTechnique中的step函数,默认对active stash中的states的操作
    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        l.debug("STASH STATUS: active: %d, staging: %d", len(simgr.stashes[self.src_stash]),
                len(simgr.stashes[self.staging_stash]))

        states = simgr.stashes[self.src_stash]
        staged_states = simgr.stashes.setdefault(self.staging_stash, []) if self.staging_stash else []

        # 如果active stash 中的states个数小于min,即active中的states个数较小
        if len(states) < self.min:
            missing = (self.max + self.min) // 2 - len(states)
            l.debug("Too few states (%d/%d) in stash %s.", len(states), self.min, self.src_stash)
            # 若现在staging_stash不为空
            if self.staging_stash:
                # 从staging_stash中回收states
                l.debug("... retrieving states from staging stash (%s)", self.staging_stash)
                # 先将staged_states中的states按照优先级排序
                staged_states.sort(key=self.priority_key or self.state_priority)
                # 再将staged_states中前missing个states添加到active中
                states += staged_states[:missing]
                staged_states[:missing] = []
            # 否则，从磁盘中提取missing个states　
            else:
                l.debug("... staging stash disabled; unpickling states")
                states += self._unpickle(missing)

        # 如果active stash 中的states个数大于max,即active中的states个数较大
        if len(states) > self.max:
            l.debug("Too many states (%d/%d) in stash %s", len(states), self.max, self.src_stash)
            # 也是先将staging_stash中的states按照优先级排序，
            # 再将active stash中max后的多个states添加到staged_states中
            states.sort(key=self.priority_key or self.state_priority)
            staged_states += states[self.max:]
            states[self.max:] = []

        # 如果staged_states中状态太少，则在磁盘中读取最大值和最小值之间的中间值的states个数
        if len(staged_states) < self.staging_min:
            l.debug("Too few states in staging stash (%s)", self.staging_stash)
            staged_states += self._unpickle((self.staging_min + self.staging_max) // 2 - len(staged_states))

        # 如果staged_states中状态过多，将其中max后的多个states存储到磁盘中
        if len(staged_states) > self.staging_max:
            l.debug("Too many states in staging stash (%s)", self.staging_stash)
            self._pickle(staged_states[self.staging_max:])
            staged_states[self.staging_max:] = []

        # 将states和staged_states中的states分别赋给active和staging_stash中
        simgr.stashes[self.src_stash] = states
        simgr.stashes[self.staging_stash] = staged_states
        return simgr

    @staticmethod
    # 获取state的id作为优先级
    def state_priority(state):
        return id(state)


from .. import vaults
