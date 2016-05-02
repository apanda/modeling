from . import NetworkObject, Core
import z3
class PolicyFirewall (NetworkObject):
    def _init (self, node, network, context, sgroup):
        super(PolicyFirewall, self).init_fail(node)
        self.constraints = list ()
        self.fw = node.z3Node
        self.ctx = context
        self.sgroup = sgroup
        network.SaneSend(self)
        self.acls = []
        self._firewallSendRules()

    def _addConstraints (self, solver):
        solver.add(self.constraints)
        self._aclConstraints(solver)

    @property
    def z3Node (self):
        return self.fw

    def AddPolicies(self, acls):
        """acls in this case is a list of pairs of sgroup names (or True) when packets should be allowed"""
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
        t_2 = z3.Int('%s_firewall_send_t_2'%(self.fw))

        self.acl_func = z3.Function('%s_acl_func'%(self.fw), self.ctx.packet, z3.BoolSort())

        self.constraints.append(z3.ForAll([n_0, p_0, t_0], z3.Implies(self.ctx.send(self.fw, n_0, p_0, t_0), \
                                       z3.Exists([n_1, t_1], \
                                       z3.And(self.ctx.recv(n_1, self.fw, p_0, t_1),\
                                       t_1 < t_0)))))

        self.constraints.append(z3.ForAll([n_0, p_0, t_0], z3.Implies(\
                z3.And(self.ctx.send(self.fw, n_0, p_0, t_0), \
                  z3.Not(self.acl_func(p_0))), \
                z3.Exists([n_1, p_1, t_1], \
                  z3.And(self.ctx.send(self.fw, n_1, p_1, t_1), \
                         t_1 + 1 <= t_0, \
                         self.acl_func(p_1), \
                         self.ctx.packet.src(p_0) == self.ctx.packet.dest(p_1), \
                         self.ctx.packet.dest(p_0) == self.ctx.packet.src(p_1), \
                         self.ctx.src_port(p_0) == self.ctx.dest_port(p_1), \
                         self.ctx.dest_port(p_0) == self.ctx.src_port(p_1), \
                   )))))

    def _aclConstraints(self, solver):
        if len(self.acls) == 0:
            return
        #a_0 = z3.Const('%s_firewall_acl_a_0'%(self.fw), self.ctx.address)
        #a_1 = z3.Const('%s_firewall_acl_a_1'%(self.fw), self.ctx.address)
        p = z3.Const('%s_firewall_acl_p'%(self.fw), self.ctx.packet)
        conditions = []
        for (a, b) in self.acls:
            a_part = None
            b_part = None
            if isinstance(a, str):
                a_part = self.sgroup.sgPredicate(a)(self.ctx.packet.src(p))
            elif isinstance(a, bool):
                a_part = a
            else:
                assert(False)

            if isinstance(b, str):
                b_part = self.sgroup.sgPredicate(b)(self.ctx.packet.dest(p))
            elif isinstance(b, bool):
                b_part = b
            else:
                assert(False)
            if isinstance(a, bool) and isinstance(b, bool):
                solver.add(z3.ForAll([p], self.acl_func(p) == (a and b)))
                return


            conditions.append(z3.And(a_part, b_part))
        solver.add(z3.ForAll([p], self.acl_func(p) == z3.Or(conditions)))
