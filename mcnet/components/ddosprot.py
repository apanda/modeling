from . import NetworkObject, Core
import z3
class DDOSProtection (NetworkObject):
    def _init (self, node, network, context):
        super(DDOSProtection, self).init_fail(node)
        self.constraints = list ()
        self.dpi = node.z3Node
        self.ctx = context
        network.SaneSend(self)
        self.acls = []
        self.failed = z3.Function('%s_dpi_failed'%(self.dpi), z3.IntSort(), z3.BoolSort())
        self.ddos = z3.Function('%s_dpi_trigger'%(self.dpi), self.ctx.address, z3.IntSort(), z3.BoolSort())
        self._ddosSendRules()

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _ddosSendRules(self):
        p_0 = z3.Const('%s_dpi_send_p_0'%(self.dpi), self.ctx.packet)
        p_1 = z3.Const('%s_dpi_send_p_1'%(self.dpi), self.ctx.packet)
        n_0 = z3.Const('%s_dpi_send_n_0'%(self.dpi), self.ctx.node)
        n_1 = z3.Const('%s_dpi_send_n_1'%(self.dpi), self.ctx.node)
        t_0 = z3.Int('%s_dpi_send_t_0'%(self.dpi))
        t_1 = z3.Int('%s_dpi_send_t_1'%(self.dpi))
        t_2 = z3.Int('%s_dpi_send_t_2'%(self.dpi))
        t_3 = z3.Int('%s_dpi_send_t_3'%(self.dpi))
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], z3.Implies(self.ctx.send(self.dpi, n_0, p_0, t_0), \
                                       z3.And(z3.Not(self.failed(t_0)), \
                                       z3.Exists([n_1, t_1], \
                                       z3.And(self.ctx.recv(n_1, self.dpi, p_0, t_1), \
                                              t_1 < t_0, \
                                              z3.Not(self.failed(t_1)), \
                                              z3.ForAll([t_2], \
                                                z3.Or(z3.Not(self.ddos(self.ctx.packet.src(p_0), t_2)), \
                                                  z3.Exists([t_3], \
                                                    z3.And(t_2 < t_3, t_3 < t_0, t_3 < t_1, self.failed(t_3)))))))))))

    @property
    def z3Node (self):
        return self.dpi
