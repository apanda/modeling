from . import NetworkObject, Core
import z3
class AllowAll (NetworkObject):
    def _init (self, node, network, context):
        super(AllowAll, self).init_fail(node)
        self.constraints = list ()
        self.node = node.z3Node
        self.ctx = context
        network.SaneSend(self)
        self._rules()

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _rules(self):
        p_0 = z3.Const('%s_send_p_0'%(self.node), self.ctx.packet)
        n_0 = z3.Const('%s_send_n_0'%(self.node), self.ctx.node)
        n_1 = z3.Const('%s_send_n_1'%(self.node), self.ctx.node)
        t_0 = z3.Int('%s_send_t_0'%(self.node))
        t_1 = z3.Int('%s_send_t_1'%(self.node))
        self.constraints.append(\
                z3.ForAll([n_0, p_0, t_0], z3.Implies(self.ctx.send(self.node, n_0, p_0, t_0), \
                   z3.And(z3.Not(self.failed(t_0)), \
                       z3.Exists([n_1, t_1], \
                          z3.And(self.ctx.recv(n_1, self.node, p_0, t_1), \
                          t_1 < t_0, \
                          z3.Not(self.failed(t_1))))))))
                        
    @property
    def z3Node (self):
        return self.node
