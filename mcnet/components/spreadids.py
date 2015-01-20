from . import NetworkObject, Core
import z3
class SpreadIDS (NetworkObject):
    def _init (self, node, network, context, shunt_to):
        self.constraints = list()
        self.node = node.z3Node
        self.shunt = shunt_to.z3Node
        self.ctx = context
        self.net = network
        self.constraints = []
        self.net.SaneSend(self)
        self.suspicious = z3.Function('%s_suspicious?'%(self.node), self.ctx.packet, z3.BoolSort())
        self._idsSendRules()

    @property
    def z3Node (self):
        return self.node

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _idsSendRules (self):
        p_0 = z3.Const('%s_p_0'%(self.node), self.ctx.packet)
        n_0 = z3.Const('%s_n_0'%(self.node), self.ctx.node)
        n_1 = z3.Const('%s_n_1'%(self.node), self.ctx.node)
        t_0 = z3.Int('%s_t_0'%self.node)
        t_1 = z3.Int('%s_t_1'%self.node)
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], z3.Implies(self.ctx.send(self.node, n_0, p_0, t_0), \
                                   z3.Exists([n_1, t_1], \
                                     z3.And(self.ctx.recv(n_1, self.node, p_0, t_1), \
                                            t_1 < t_0)))))
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
                z3.Implies(z3.And(self.ctx.send(self.node, n_0, p_0, t_0), \
                                  self.suspicious(p_0)), \
                            n_0 == self.shunt)))
