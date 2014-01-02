from . import NetworkObject, Core
import z3
class IPS (NetworkObject):
    """ Intrusion prevention system: Just combines a stateful ips with DPI, hooray""" 
    def _init (self, policy, node, network, context):
        """Policy is an object of type dpi_policy"""
        self.constraints = list ()
        self.policy = policy
        self.ips = node
        self.ctx = context
        network.SaneSend(self)
        self._ipsFunctions ()
        self._ipsSendRules ()
        self.acls = []

    def _addConstraints (self, solver):
        solver.add(self.constraints)
        p = z3.Const('__ips_acl_Packet_%s'%(self.ips), self.ctx.packet)
        addr_a = z3.Const ('__ips_acl_cache_a_%s'%(self.ips), self.ctx.address)
        port_a = z3.Const('__ips_acl_port_a_%s'%(self.ips), z3.IntSort())
        addr_b = z3.Const ('__ips_acl_cache_b_%s'%(self.ips), self.ctx.address)
        port_b = z3.Const('__ips_acl_port_b_%s'%(self.ips), z3.IntSort())
        aclConstraints = map(lambda (a, b): z3.And(self.ctx.packet.src(p) == a, \
                                              self.ctx.packet.dest(p) == b),
                                              self.acls)
        if len(aclConstraints) == 0:
            aclConstraints = [True]
        eh = z3.Const('__ips_acl_node_%s'%(self.ips), self.ctx.node)

        # Constraints for what holes are punched 
        # \forall a, b cached(a, b) \iff \exists e, p send(f, e, p) \land 
        #                 p.src == a \land p.dest == b \land ctime(a, b) = etime(ips, p, R) \land
        #                   neg(ACL(p))
        solver.add(z3.ForAll([addr_a, port_a, addr_b, port_b], self.cached(addr_a, port_a, addr_b, port_b) ==\
                       z3.Exists([eh, p], \
                           z3.And(self.ctx.recv(eh, self.ips, p), \
                           z3.And(self.ctx.packet.src (p) == addr_a, self.ctx.packet.dest(p) == addr_b, \
                                   self.ctx.src_port (p) == port_a,  self.ctx.dest_port (p) == port_b, \
                                   self.ctime (addr_a, port_a, addr_b, port_b) == self.ctx.etime(self.ips, p, self.ctx.recv_event), \
                                   z3.Not(z3.Or(aclConstraints)))))))

    @property
    def z3Node (self):
        return self.ips

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
   
    def _ipsFunctions (self):
        self.cached = z3.Function ('__ips_cached_rules_%s'%(self.ips), self.ctx.address, z3.IntSort(), self.ctx.address, z3.IntSort(), z3.BoolSort())
        self.ctime = z3.Function ('__ips_cached_time_%s'%(self.ips), self.ctx.address, z3.IntSort(), self.ctx.address, z3.IntSort(), z3.IntSort())
        addr_a = z3.Const ('__ips_addr_cache_a_%s'%(self.ips), self.ctx.address)
        port_a = z3.Const('__ips_addr_port_a_%s'%(self.ips), z3.IntSort())
        addr_b = z3.Const ('__ips_addr_cache_b_%s'%(self.ips), self.ctx.address)
        port_b = z3.Const('__ips_addr_port_b_%s'%(self.ips), z3.IntSort())
        self.constraints.append(z3.ForAll([addr_a, port_a, addr_b, port_b], z3.Implies(\
                        z3.Or(port_a < 0, \
                              port_a > Core.MAX_PORT, \
                              port_b < 0, \
                              port_a > Core.MAX_PORT), \
                        z3.Not(self.cached(addr_a, port_a, addr_b, port_b)))))
        self.constraints.append(z3.ForAll([addr_a, port_a, addr_b, port_b], self.ctime (addr_a, port_a, addr_b, port_b) \
                                            >= 0))
        self.constraints.append(z3.ForAll([addr_a, port_a, addr_b, port_b], z3.Implies(\
                        z3.Not(self.cached(addr_a, port_a, addr_b, port_b)), \
                        self.ctime (addr_a, port_a, addr_b, port_b) == 0)))

    def _ipsSendRules (self):
        p = z3.Const('__ips_Packet_%s'%(self.ips), self.ctx.packet)
        eh = z3.Const('__ips_node1_%s'%(self.ips), self.ctx.node)
        eh2 = z3.Const('__ips_node2_%s'%(self.ips), self.ctx.node)
        eh3 = z3.Const('__ips_node3_%s'%(self.ips), self.ctx.node)

        # The ips never invents packets
        # \forall e_1, p\ send (f, e_1, p) \Rightarrow \exists e_2 recv(e_2, f, p)
        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.ips, eh, p), \
                z3.Exists([eh2], \
                 z3.And(self.ctx.recv(eh2, self.ips, p), \
                    z3.Not(z3.Exists([eh3], z3.And(self.ctx.send(self.ips, eh3, p),\
                                                   eh3 != eh))), \
                    self.ctx.etime(self.ips, p, self.ctx.recv_event) < \
                        self.ctx.etime(self.ips, p, self.ctx.send_event))))))

        # Actually enforce ips rules
        # \forall e_1, p send(f, e_1, p) \Rightarrow (cached(p.src, p.dest)
        #                       \land ctime(p.src, p.dest) <= etime(ips, p, R))
        #                       \lor (cached(p.dest, p.src) \land ctime(p.dest, p.src) <= etime(ips. p, R))
        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.ips, eh, p), \
                 z3.And(z3.Not(self.policy.dpi_match(self.ctx.packet.body(p))), \
                        z3.Or(z3.And(self.cached(self.ctx.packet.src(p), self.ctx.src_port(p), self.ctx.packet.dest(p), self.ctx.dest_port(p)), \
                                        self.ctime(self.ctx.packet.src(p), self.ctx.src_port(p), self.ctx.packet.dest(p), self.ctx.dest_port(p)) <\
                                                        self.ctx.etime(self.ips, p, self.ctx.recv_event)), \
                              z3.And(self.cached(self.ctx.packet.dest(p), self.ctx.dest_port(p), self.ctx.packet.src(p), self.ctx.src_port(p)), \
                                        self.ctime(self.ctx.packet.dest(p), self.ctx.dest_port(p), self.ctx.packet.src(p), self.ctx.src_port(p)) <\
                                                        self.ctx.etime(self.ips, p, self.ctx.recv_event)))))))
