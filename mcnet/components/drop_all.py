from . import NetworkObject, Core
import z3
class DropAll (NetworkObject):
    def _init (self, node, network, context):
        super(DropAll, self).init_fail(node)
        self.constraints = list ()
        self.node = node.z3Node
        self.ctx = context
        network.SaneSend(self)
        self._ddosSendRules()

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _ddosSendRules(self):
        p_0 = z3.Const('%s_dpi_send_p_0'%(self.node), self.ctx.packet)
        n_0 = z3.Const('%s_dpi_send_n_0'%(self.node), self.ctx.node)
        t_0 = z3.Int('%s_dpi_send_t_0'%(self.node))
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], z3.Not(self.ctx.send(self.node, n_0, p_0, t_0))))
    @property
    def z3Node (self):
        return self.node
