from . import NetworkObject
import z3
class EndHost (NetworkObject):
    """End host objects"""
    def _init (self, node, network, context):
        self.constraints = list ()
        self.ctx = context
        self.node = node
        self._endHostRules()

    @property
    def z3Node (self):
        return self.node

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _endHostRules (self):
        eh = z3.Const('__nodeRules_Node', self.ctx.node)
        p = z3.Const('__nodeRules_Packet', self.ctx.packet)
        # \forall e_1, p: send(h, e_1, p) \Rightarrow hostHasAddr (h, p.src)
        # \forall e_1, p: send(h, e_1, p) \Rightarrow p.origin = h
        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.node, eh, p), \
            self.ctx.hostHasAddr(self.node, self.ctx.packet.src(p)))))
        self.constraints.append(z3.ForAll([eh, p],
            z3.Implies(self.ctx.send(self.node, eh, p), \
                    self.ctx.packet.origin(p) ==\
                                self.node)))

    @property
    def isEndHost (self):
        return True
