from . import NetworkObject
import z3

class IsolatedWebProxy (NetworkObject):
    """A caching web proxy"""
    def _init (self, node, network, context):
        self.proxy = node
        self.ctx = context
        self.constraints = list ()
        network.SaneSend(self)
        self._webProxyFunctions ()
        self._webProxyConstraints ()
    
    @property
    def z3Node (self):
        return self.proxy 

    def _addConstraints (self, solver):
        solver.add(self.constraints)
    
    # TODO: Add some constraints to take care of isolation policies
    def _webProxyConstraints (self):
        p = z3.Const('__webproxy_constraint_packet1_%s'%(self.proxy), self.ctx.packet)
        p2 = z3.Const('__webproxy_constraint_p2_%s'%(self.proxy), self.ctx.packet)
        eh = z3.Const('__webproxy_contraint_eh_%s'%(self.proxy), self.ctx.node)
        eh2 = z3.Const('__webproxy_contraint_eh2_%s'%(self.proxy), self.ctx.node)
        # \forall e, p: send(w, e, p) \Rightarrow hostHasAddr(w, p.src)
        # \forall e_1, p_1: send(w, e, p_1) \Rightarrow \exists e_2, p_2: recv(e_2, w, p_2) \land 
        #                   p_2.origin == p_1.origin \land p_2.dest == p_1.dest \land hostHasAddr(p_2.origin, p_2.src)
        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.proxy, eh, p), \
                            self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p)))))

        cached_packet = z3.And(self.cached(self.ctx.packet.dest(p2), self.ctx.packet.body(p2)), \
                                self.ctx.etime(self.proxy, p2, self.ctx.recv_event) > \
                                    self.ctime(self.ctx.packet.dest(p2), self.ctx.packet.body(p2)), \
                                self.ctx.packet.body(p) == self.cresp(self.ctx.packet.dest(p2), self.ctx.packet.body(p2)), \
                                self.ctx.packet.dest(p) == self.ctx.packet.src(p2), \
                                self.ctx.dest_port(p) == self.ctx.src_port(p2), \
                                self.ctx.src_port(p) == self.ctx.dest_port(p2), \
                                self.ctx.packet.origin(p) == self.corigin(self.ctx.packet.dest(p2), self.ctx.packet.body(p2)))

        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.proxy, eh, p), 
                                z3.Exists([p2, eh2], 
                                    z3.And(self.ctx.recv(eh2, self.proxy, p2),
                                      z3.Not(self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p2))),\
                                      z3.Or(\
                                        z3.And(z3.Not(self.ctx.hostHasAddr(self.proxy, self.ctx.packet.dest(p2))), \
                                               self.ctx.packet.origin(p2) == self.ctx.packet.origin(p),
                                               self.ctx.packet.dest(p2) == self.ctx.packet.dest(p), \
                                               self.ctx.packet.body(p2) == self.ctx.packet.body(p), \
                                               self.ctx.packet.seq(p2) == self.ctx.packet.seq(p), \
                                               self.ctx.hostHasAddr(self.ctx.packet.origin(p2), self.ctx.packet.src(p2)), \
                                               self.ctx.dest_port(p2) == self.ctx.dest_port(p), \
                                               self.ctx.etime(self.proxy, p, self.ctx.send_event) > \
                                                    self.ctx.etime(self.proxy, p2, self.ctx.recv_event), \
                                               self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p))), \
                                        cached_packet))))))
    
    def _webProxyFunctions (self):
        self.cached = z3.Function('__webproxy_cached_%s'%(self.proxy), self.ctx.address, z3.IntSort(), z3.BoolSort())
        self.ctime = z3.Function('__webproxy_ctime_%s'%(self.proxy), self.ctx.address, z3.IntSort(), z3.IntSort())
        self.cresp = z3.Function('__webproxy_cresp_%s'%(self.proxy), self.ctx.address, z3.IntSort(), z3.IntSort())
        self.corigin = z3.Function('__webproxy_corigin_%s'%(self.proxy), self.ctx.address, z3.IntSort(), self.ctx.node)

        a1 = z3.Const('__webproxyfunc_cache_addr_%s'%(self.proxy), self.ctx.address)
        i1 = z3.Const('__webproxyfunc_cache_id_%s'%(self.proxy), z3.IntSort())

        # Model cache as a function
        # If not cached, cache time is 0
        self.constraints.append(z3.ForAll([a1, i1], z3.Not(self.cached(a1, i1)) == (self.ctime(a1, i1) == 0)))
        self.constraints.append(z3.ForAll([a1, i1], z3.Not(self.cached(a1, i1)) == (self.cresp(a1, i1) == 0)))
        p = z3.Const('__webproxy_packet1_%s'%(self.proxy), self.ctx.packet)
        p2 = z3.Const('__webproxy_p2_%s'%(self.proxy), self.ctx.packet)
        eh = z3.Const('__webproxy_eh_%s'%(self.proxy), self.ctx.node)
        cache_condition = z3.ForAll([a1, i1],
                            z3.Implies(self.cached(a1, i1), \
                              z3.Exists([p, eh], \
                                z3.Not(self.ctx.hostHasAddr(self.proxy, a1)), \
                                self.ctx.recv(eh, self.proxy, p), \
                                self.ctx.packet.src(p) == a1, \
                                self.ctx.packet.body(p) == self.cresp(a1, i1), \
                                self.corigin(a1, i1) == self.ctx.packet.origin(p), \
                                self.ctx.hostHasAddr(self.proxy, self.ctx.packet.dest(p)), \
                                self.ctx.etime (self.proxy, p, self.ctx.recv_event) == self.ctime(a1, i1)
        cache_condition = z3.ForAll([a1, i1], \
                            z3.Implies(self.cached(a1, i1), \
                             z3.Exists([p, eh], \
                              z3.And(\
                                z3.Not(self.ctx.hostHasAddr(self.proxy, a1)), \
                                self.ctx.recv(eh, self.proxy, p), \
                                self.ctx.packet.src(p) == a1, \
                                self.ctx.packet.body(p) == self.cresp(a1, i1), \
                                self.corigin(a1, i1) == self.ctx.packet.origin(p), \
                                self.ctx.hostHasAddr(self.proxy, self.ctx.packet.dest(p)), \
                                self.ctx.etime (self.proxy, p, self.ctx.recv_event) == self.ctime(a1, i1), \
                                z3.Exists([p2], \
                                z3.And(\
                                    self.ctx.etime(self.proxy, p2, self.ctx.send_event) > 0, \
                                    self.ctx.etime(self.proxy, p2, self.ctx.send_event) < self.ctime(a1, i1), \
                                    self.ctx.etime(self.ctx.addrToHost(a1), p, self.ctx.send_event) > 
                                        self.ctx.etime(self.ctx.addrToHost(a1), p2, self.ctx.recv_event), \
                                    self.ctx.packet.dest(p2) == a1, \
                                    self.ctx.packet.body(p2) == i1, \
                                    self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p2)), \
                                    self.ctx.packet.origin(p2) != self.proxy
                                ))))))
        self.constraints.append(cache_condition)
