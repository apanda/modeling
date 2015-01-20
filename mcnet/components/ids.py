from . import NetworkObject, Core
import z3

class LearningFirewall (NetworkObject):
    def _init (self, node, network, context):
        self.constraints = list ()
        self.fw = node.z3Node
        self.ctx = context
        network.SaneSend(self)
        self.acls = []
        self._firewallSendRules()

    def _addConstraints (self, solver):
        solver.add(self.constraints)
        self._aclConstraints(solver)

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
    def ACLs (self):
        return self.acls

    def _firewallSendRules(self):
        p_0 = z3.Const('%s_firewall_send_p_0'%(self.fw), self.ctx.packet)
        p_1 = z3.Const('%s_firewall_send_p_1'%(self.fw), self.ctx.packet)
        n_0 = z3.Const('%s_firewall_send_n_0'%(self.fw), self.ctx.node)
        n_1 = z3.Const('%s_firewall_send_n_1'%(self.fw), self.ctx.node)
        t_0 = z3.Int('%s_firewall_send_t_0'%(self.fw))
        t_1 = z3.Int('%s_firewall_send_t_1'%(self.fw))
        self.acl_func = z3.Function('%s_acl_func'%(self.fw), self.ctx.address, self.ctx.address, z3.BoolSort())
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], z3.Implies(self.ctx.send(self.fw, n_0, p_0, t_0), \
                                       z3.Exists([n_1, t_1], \
                                       z3.And(self.ctx.recv(n_1, self.fw, p_0, t_1), \
                                              t_1 < t_0)))))

        self.constraints.append(z3.ForAll([n_0, p_0, t_0], z3.Implies(\
                z3.And(self.ctx.send(self.fw, n_0, p_0, t_0), \
                  z3.Not(self.acl_func(self.ctx.packet.src(p_0), self.ctx.packet.dest(p_0)))), \
                z3.Exists([n_1, p_1, t_1], \
                  z3.And(self.ctx.send(self.fw, n_1, p_1, t_1), \
                         t_1 + 1 <= t_0, \
                         self.acl_func(self.ctx.packet.src(p_1), self.ctx.packet.dest(p_1)), \
                         self.ctx.packet.src(p_0) == self.ctx.packet.dest(p_1), \
                         self.ctx.packet.dest(p_0) == self.ctx.packet.src(p_1), \
                         self.ctx.src_port(p_0) == self.ctx.dest_port(p_1), \
                         self.ctx.dest_port(p_0) == self.ctx.src_port(p_1))))))

    def _aclConstraints(self, solver):
        if len(self.acls) == 0:
            return
        a_0 = z3.Const('%s_firewall_acl_a_0'%(self.fw), self.ctx.address)
        a_1 = z3.Const('%s_firewall_acl_a_1'%(self.fw), self.ctx.address)
        acl_map = map(lambda (a, b): z3.And(a_0 == a, a_1 == b), self.acls)
        solver.add(z3.ForAll([a_0, a_1], self.acl_func(a_0, a_1) == z3.Not(z3.Or(acl_map))))
