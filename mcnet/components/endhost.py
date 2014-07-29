from . import NetworkObject
import z3
class EndHost (NetworkObject):
    """End host objects"""
    def _init (self, node, network, context):
        self.constraints = list ()
        self.ctx = context
        self.node = node.z3Node
        self._endHostRules()

    @property
    def z3Node (self):
        return self.node

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _endHostRules (self):
        n_0 = z3.Const('eh_%s_n_0'%(self.node), self.ctx.node)
        t_0 = z3.Int('eh_%s_t_0'%(self.node))
        p_0 = z3.Const('eh_%s_p_0'%(self.node), self.ctx.packet)
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
                z3.Implies(self.ctx.send(self.node, n_0, p_0, t_0), \
                self.ctx.nodeHasAddr(self.node, self.ctx.packet.src(p_0)))))
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
                z3.Implies(self.ctx.send(self.node, n_0, p_0, t_0), \
                self.ctx.packet.origin(p_0) == self.node)))
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
                z3.Implies(self.ctx.send(self.node, n_0, p_0, t_0), \
                self.ctx.packet.orig_body(p_0) == self.ctx.packet.body(p_0))))
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
                z3.Implies(self.ctx.recv(n_0, self.node, p_0, t_0), \
                self.ctx.nodeHasAddr(self.node, self.ctx.packet.dest(p_0)))))

    @property
    def isEndHost (self):
        return True
