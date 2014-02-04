"""Problem statement for finding a (minimal) subgraph on which an invariant is RONO"""
# TODO: Generalize to more general invariants. This is actually more a TODO for the property checker which I must have
# written in some sort of a drunken daze. But leaving this here since this is the proximate cause of my sadness.

class SubgraphProblem (object):
    """A handy class to pass in all the inputs to the problem"""
    def __init__ (self, ctx):
        self._network = None
        self._ctx = ctx
        self._node_map = None
        self._tfunctions = None
        self._origin = None
        self._target = None

    @property
    def origin (self):
        """The origin of packets we want to isolate"""
        return self._origin
    @origin.setter
    def origin (self, origin):
        self._origin = origin

    @property
    def target (self):
        """The target of our isolation property: i.e. we want to make sure origin cannot send to target"""
        return self._target
    @target.setter
    def target (self, tgt):
        self._target = tgt

    @property
    def ctx (self):
        """Context for the problem"""
        return self._ctx

    @property
    def network (self):
        """Network for the problem. We assume none of the nodes have been attached."""
        return self._network
    @network.setter
    def network (self, net):
        self._network = net

    @property
    def node_map (self):
        """Dictionary of string -> network objects."""
        return self._node_map
    @node_map.setter
    def node_map (self, net):
        self._node_map = net

    @property
    def tfunctions (self):
        """Transfer functions, 'coz you know they are useful"""
        return self._tfunctions
    @tfunctions.setter
    def tfunctions (self, net):
        self._tfunctions = net
