from . import NetworkObject
class DumbNode (NetworkObject):
    """This is just a wrapper around z3 instances. The idea is that by using this we perhaps need to have fewer (or no)
    ifs to deal with the case where we don't instantiate an object for a node"""
    def _init (self, node):
        super(DumbNode, self).init_fail(node)
        self.node = node

    @property
    def z3Node (self):
        return self.node

    def _addConstraints (self, solver):
        pass
