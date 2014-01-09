from . import NetworkObject
import z3

class ErroneousAclWebProxy (NetworkObject):
    """A caching web proxy which enforces ACLs erroneously.
       The idea here was to present something that is deliberately not path independent"""
    def _init (self, node, network, context):
        self.proxy = node.z3Node
        self.ctx = context
        self.constraints = list ()
        self.acls = list ()
        network.SaneSend(self)
        self._webProxyFunctions ()
        self._webProxyConstraints ()

    @property
    def z3Node (self):
        return self.proxy

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

    def _addConstraints (self, solver):
        self.constraints = list ()
        self._webProxyFunctions ()
        self._webProxyConstraints ()
        solver.add(self.constraints)

    def _webProxyConstraints (self):
        eh = z3.Const('__webproxy_contraint_eh_%s'%(self.proxy), self.ctx.node)
        eh2 = z3.Const('__webproxy_contraint_eh2_%s'%(self.proxy), self.ctx.node)
        a = z3.Const('__webproxyfunc_cache_addr_%s'%(self.proxy), self.ctx.address)
        i = z3.Const('__webproxyfunc_cache_body_%s'%(self.proxy), z3.IntSort())
        p = z3.Const('__webproxy_req_packet_%s'%(self.proxy), self.ctx.packet)
        p2 = z3.Const('__webproxy_req_packet_2_%s'%(self.proxy), self.ctx.packet)
        p3 = z3.Const('__webproxy_res_packet_%s'%(self.proxy), self.ctx.packet)
        e1 = z3.Const('__webproxy_e1_%s'%(self.proxy), self.ctx.node)
        e2 = z3.Const('__webproxy_e2_%s'%(self.proxy), self.ctx.node)
        e3 = z3.Const('__webproxy_e3_%s'%(self.proxy), self.ctx.node)
        e4 = z3.Const('__webproxy_e4_%s'%(self.proxy), self.ctx.node)
        e5 = z3.Const('__webproxy_e5_%s'%(self.proxy), self.ctx.node)
        e6 = z3.Const('__webproxy_e6_%s'%(self.proxy), self.ctx.node)

        # \forall e, p: send(w, e, p) \Rightarrow hostHasAddr(w, p.src)
        # \forall e_1, p_1: send(w, e, p_1) \Rightarrow \exists e_2, p_2: recv(e_2, w, p_2) \land
        #                   p_2.origin == p_1.origin \land p_2.dest == p_1.dest \land hostHasAddr(p_2.origin, p_2.src)
        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.proxy, eh, p), \
                            self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p)))))

        cached_packet = z3.And(self.cached(self.ctx.packet.dest(p2), self.ctx.packet.body(p2)), \
                                self.ctx.etime(self.proxy, p2, self.ctx.recv_event) > \
                                    self.ctime(self.ctx.packet.dest(p2), self.ctx.packet.body(p2)), \
                                self.ctx.etime(self.proxy, p, self.ctx.send_event) > \
                                    self.ctx.etime(self.proxy, p2, self.ctx.recv_event), \
                                self.ctx.packet.body(p) == self.cresp(self.ctx.packet.dest(p2), self.ctx.packet.body(p2)), \
                                self.ctx.packet.dest(p) == self.ctx.packet.src(p2), \
                                self.ctx.dest_port(p) == self.ctx.src_port(p2), \
                                self.ctx.src_port(p) == self.ctx.dest_port(p2), \
                                self.ctx.packet.options(p) == 0, \
                                self.ctx.packet.origin(p) == self.corigin(self.ctx.packet.dest(p2), self.ctx.packet.body(p2)))

        request_constraints = [z3.Not(self.ctx.hostHasAddr(self.proxy, self.ctx.packet.dest(p2))), \
                               self.ctx.packet.origin(p2) == self.ctx.packet.origin(p),
                               self.ctx.packet.dest(p2) == self.ctx.packet.dest(p), \
                               self.ctx.packet.body(p2) == self.ctx.packet.body(p), \
                               self.ctx.packet.options(p) == 0, \
                               self.ctx.packet.seq(p2) == self.ctx.packet.seq(p), \
                               self.ctx.hostHasAddr(self.ctx.packet.origin(p2), self.ctx.packet.src(p2)), \
                               self.ctx.dest_port(p2) == self.ctx.dest_port(p), \
                               self.ctx.etime(self.proxy, p, self.ctx.send_event) > \
                                  self.ctx.etime(self.proxy, p2, self.ctx.recv_event), \
                               self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p))]
        if len(self.acls) != 0:
            acl_constraint = map(lambda (s, d): \
                                            z3.Not(z3.And(self.ctx.packet.src(p2) == s, \
                                                   self.ctx.packet.dest(p2) == d)), self.acls)
            request_constraints.extend(acl_constraint)

        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.proxy, eh, p), \
                                z3.Or(\
                                    z3.Exists([p2, eh2], \
                                        z3.And(self.ctx.recv(eh2, self.proxy, p2), \
                                        z3.Not(self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p2))),\
                                        z3.And(request_constraints))), \
                                    z3.Exists([p2, eh2], \
                                        z3.And(self.ctx.recv(eh2, self.proxy, p2), \
                                        z3.Not(self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p2))),\
                                        cached_packet))))))

        cache_conditions = \
                z3.ForAll([a, i], \
                    z3.Implies(self.cached(a, i), \
                        z3.And(\
                           z3.Not(self.ctx.hostHasAddr (self.proxy, a)), \
                           z3.Exists([e1, e2, e3, p, p2, p3], \
                             z3.And(\
                               self.ctx.recv(e1, self.proxy, p2), \
                               self.ctx.packet.dest(p2) == a, \
                               self.ctx.packet.body(p2) == i, \
                               self.ctx.packet.body(p) == i, \
                               self.ctx.packet.dest(p) == a, \
                               self.ctx.dest_port(p) == self.ctx.dest_port(p2), \
                               self.creqpacket(a, i) == p2, \
                               self.creqopacket(a, i) == p, \
                               self.ctime(a, i) > self.ctx.etime(self.proxy, p2, self.ctx.recv_event), \
                               self.ctx.send(self.proxy, e2, p), \
                               self.ctime(a, i) > self.ctx.etime(self.proxy, p, self.ctx.send_event), \
                               self.ctx.recv(e3, self.proxy, p3), \
                               self.crespacket(a, i) == p3, \
                               self.ctx.src_port(p3) == self.ctx.dest_port(p), \
                               self.ctx.dest_port(p3) == self.ctx.src_port(p), \
                               self.ctx.packet.src(p3) == self.ctx.packet.dest(p), \
                               self.ctx.packet.dest(p3) == self.ctx.packet.src(p), \
                               z3.Exists([e5, e6], \
                                 z3.And(
                                   self.ctx.hostHasAddr (e5, a), \
                                   self.ctx.recv(e6, e5, p), \
                                   z3.ForAll([e4], \
                                    z3.Or(self.ctx.etime(e4, p3, self.ctx.send_event) == 0, \
                                          self.ctx.etime(e4, p3, self.ctx.send_event) > self.ctx.etime(e5, p, self.ctx.recv_event))))), \
                               self.cresp(a, i) == self.ctx.packet.body(p3), \
                               self.corigin(a, i) == self.ctx.packet.origin(p3), \
                               self.ctime(a, i) == self.ctx.etime(self.proxy, p3, self.ctx.recv_event), \
                               *request_constraints)))))
        self.constraints.append(cache_conditions)

    def _webProxyFunctions (self):
        self.cached = z3.Function('__webproxy_cached_%s'%(self.proxy), self.ctx.address, z3.IntSort(), z3.BoolSort())
        self.ctime = z3.Function('__webproxy_ctime_%s'%(self.proxy), self.ctx.address, z3.IntSort(), z3.IntSort())
        self.cresp = z3.Function('__webproxy_cresp_%s'%(self.proxy), self.ctx.address, z3.IntSort(), z3.IntSort())
        self.corigin = z3.Function('__webproxy_corigin_%s'%(self.proxy), self.ctx.address, z3.IntSort(), self.ctx.node)
        self.crespacket = z3.Function('__webproxy_crespacket_%s'%(self.proxy), self.ctx.address, z3.IntSort(), self.ctx.packet)
        self.creqpacket = z3.Function('__webproxy_creqpacket_%s'%(self.proxy), self.ctx.address, z3.IntSort(), self.ctx.packet)
        self.creqopacket = z3.Function('__webproxy_creqopacket_%s'%(self.proxy), self.ctx.address, z3.IntSort(), self.ctx.packet)

        a = z3.Const('__webproxyfunc_cache_addr_%s'%(self.proxy), self.ctx.address)
        i = z3.Const('__webproxyfunc_cache_body_%s'%(self.proxy), z3.IntSort())

        # Model cache as a function
        # If not cached, cache time is 0
        self.constraints.append(z3.ForAll([a, i], z3.Not(self.cached(a, i)) == (self.ctime(a, i) == 0)))
        self.constraints.append(z3.ForAll([a, i], z3.Not(self.cached(a, i)) == (self.cresp(a, i) == 0)))
