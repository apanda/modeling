from . import NetworkObject
import z3
class AclFirewall (NetworkObject):
    def _init(self, node, network, context):
        self.fw = node.z3Node
        self.ctx = context
        self.constraints = list ()
        self.acls = list ()
        network.SaneSend (self)
        self._firewallSendRules ()

    @property
    def z3Node (self):
        return self.fw

    def SetPolicy (self, policy):
        """Wrap add acls"""
        self.AddAcls(policy)

    def AddAcls(self, acls):
        if not isinstance(acls, list):
            acls = [acls]
        self.acls.extend(acls)

    @property
    def ACLs(self):
        return self.acls

    def _addConstraints(self, solver):
        solver.add(self.constraints)
        self._aclConstraints(solver)

    def _firewallSendRules(self):
        p_0 = z3.Const('%s_firewall_send_p_0'%(self.fw), self.ctx.packet)
        n_0 = z3.Const('%s_firewall_send_n_0'%(self.fw), self.ctx.node)
        n_1 = z3.Const('%s_firewall_send_n_1'%(self.fw), self.ctx.node)
        t_0 = z3.Int('%s_firewall_send_t_0'%(self.fw))
        t_1 = z3.Int('%s_firewall_send_t_1'%(self.fw))
        self.acl_func = z3.Function('%s_acl_func'%(self.fw), self.ctx.address, self.ctx.address, z3.BoolSort())

        self.constraints.append(z3.ForAll([n_0, p_0, t_0],
            z3.Implies(self.ctx.send(self.fw, n_0, p_0, t_0), \
                    z3.Exists([t_1], \
                        z3.And(t_1 < t_0, \
                        z3.Exists([n_1], \
                            self.ctx.recv(n_1, self.fw, p_0, t_1)), \
                        z3.Not(self.acl_func(self.ctx.packet.src(p_0), self.ctx.packet.dest(p_0))))))))

    def _aclConstraints(self, solver):
        if len(self.acls) == 0:
            return
        a_0 = z3.Const('%s_firewall_acl_a_0'%(self.fw), self.ctx.address)
        a_1 = z3.Const('%s_firewall_acl_a_1'%(self.fw), self.ctx.address)
        acl_map = map(lambda (a, b): z3.Or(z3.And(a_0 == a, a_1 == b), z3.And(a_0 == b, a_1 == a)), self.acls)
        solver.add(z3.ForAll([a_0, a_1], self.acl_func(a_0, a_1) == z3.Or(acl_map)))
