from . import NetworkObject
import z3

class ContentCache (NetworkObject):
    """Content cache"""
    def _init (self, node, network, context):
        self.proxy = node.z3Node
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

    def _contentCacheConstraints (self):
        eh = z3.Const('__ccache_contraint_eh_%s'%(self.proxy), self.ctx.node)
        eh2 = z3.Const('__ccache_contraint_eh2_%s'%(self.proxy), self.ctx.node)
        # Conditions for the caching of packets
        a = z3.Const('__ccachefunc_cache_addr_%s'%(self.proxy), self.ctx.address)
        i = z3.Const('__ccachefunc_cache_body_%s'%(self.proxy), z3.IntSort())
        p = z3.Const('__ccache_req_packet_%s'%(self.proxy), self.ctx.packet)
        p2 = z3.Const('__ccache_req_packet_2_%s'%(self.proxy), self.ctx.packet)
        p3 = z3.Const('__ccache_res_packet_%s'%(self.proxy), self.ctx.packet)
        e1 = z3.Const('__ccache_e1_%s'%(self.proxy), self.ctx.node)
        e2 = z3.Const('__ccache_e2_%s'%(self.proxy), self.ctx.node)
        e3 = z3.Const('__ccache_e3_%s'%(self.proxy), self.ctx.node)
        e4 = z3.Const('__ccache_e4_%s'%(self.proxy), self.ctx.node)
        e5 = z3.Const('__ccache_e5_%s'%(self.proxy), self.ctx.node)
        e6 = z3.Const('__ccache_e6_%s'%(self.proxy), self.ctx.node)

        # Proxy sends its own address
        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.proxy, eh, p), \
                            self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p)))))

        # Conditions to respond from cache
        # p2 is the received request
        # p is the response sent by the content cache
        cached_packet = [self.cached(self.ctx.packet.body(p2)), \
                         self.ctx.etime(self.proxy, p2, self.ctx.recv_event) > \
                             self.ctime(self.ctx.packet.body(p2)), \
                         self.ctx.etime(self.proxy, p, self.ctx.send_event) > \
                             self.ctx.etime(self.proxy, p2, self.ctx.recv_event), \
                         self.ctx.packet.body(p) == self.cresp(self.ctx.packet.body(p2)), \
                         self.ctx.packet.orig_body(p) == self.corigbody(self.ctx.packet.body(p2)), \
                         self.ctx.packet.dest(p) == self.ctx.packet.src(p2), \
                         self.ctx.dest_port(p) == self.ctx.src_port(p2), \
                         self.ctx.src_port(p) == self.ctx.dest_port(p2), \
                         self.ctx.packet.options(p) == 0, \
                         self.ctx.packet.origin(p) == self.corigin(self.ctx.packet.body(p2))]

        # Conditions to send out a request
        # p is the new request packet.
        request_constraints = [z3.Not(self.ctx.hostHasAddr(self.proxy, self.ctx.packet.dest(p2))), \
                               self.ctx.packet.origin(p2) == self.ctx.packet.origin(p), \
                               self.ctx.packet.dest(p2) == self.ctx.packet.dest(p), \
                               self.ctx.packet.body(p2) == self.ctx.packet.body(p), \
                               self.ctx.packet.orig_body(p2) == self.ctx.packet.orig_body(p), \
                               self.ctx.packet.seq(p2) == self.ctx.packet.seq(p), \
                               self.ctx.packet.options(p) == 0, \
                               self.ctx.hostHasAddr(self.ctx.packet.origin(p2), self.ctx.packet.src(p2)), \
                               self.ctx.dest_port(p2) == self.ctx.dest_port(p), \
                               self.ctx.etime(self.proxy, p, self.ctx.send_event) > \
                                  self.ctx.etime(self.proxy, p2, self.ctx.recv_event), \
                               self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p))]

        # Condition to send out packets at all (either because a request leads to another request, or can be served from the cache)
        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.proxy, eh, p), \
                                z3.Or(\
                                    z3.Exists([p2, eh2], \
                                        z3.And(self.ctx.recv(eh2, self.proxy, p2), \
                                          z3.Not(self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p2))),\
                                          z3.And(request_constraints))), \
                                    z3.Exists([p2, eh2], \
                                        z3.And(self.ctx.recv(eh2, self.proxy, p2), \
                                          z3.Not(self.ctx.hostHasAddr(self.proxy, self.ctx.packet.src(p2))),\
                                          z3.And(cached_packet)))))))

        cache_conditions = \
                z3.ForAll([i], \
                    z3.Implies(self.cached(i), \
                           z3.Exists([e1, e2, e3, p, p2, p3, a], \
                             z3.And(\
                               z3.Not(self.ctx.hostHasAddr (self.proxy, a)), \
                               self.ctx.recv(e1, self.proxy, p2), \
                               self.ctx.packet.dest(p2) == a, \
                               self.ctx.packet.body(p2) == i, \
                               self.ctx.packet.dest(p) == a, \
                               self.ctx.packet.body(p) == i, \
                               self.ctx.dest_port(p) == self.ctx.dest_port(p2), \
                               self.creqpacket(i) == p2, \
                               self.creqopacket(i) == p, \
                               self.ctime(i) > self.ctx.etime(self.proxy, p2, self.ctx.recv_event), \
                               self.ctx.send(self.proxy, e2, p), \
                               z3.And(request_constraints), \
                               self.ctime(i) > self.ctx.etime(self.proxy, p, self.ctx.send_event), \
                               self.ctx.recv(e3, self.proxy, p3), \
                               self.crespacket(i) == p3, \
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
                                          self.ctx.etime(e4, p3, self.ctx.send_event) > self.ctx.etime(e6, p, self.ctx.recv_event))))), \
                               self.cresp(i) == self.ctx.packet.body(p3), \
                               self.corigbody(i) == self.ctx.packet.orig_body(p3), \
                               self.corigin(i) == self.ctx.packet.origin(p3), \
                               self.ctime(i) == self.ctx.etime(self.proxy, p3, self.ctx.recv_event)))))

        self.constraints.append(cache_conditions)

    def _contentCacheFunctions (self):
        # Is cached
        self.cached = z3.Function('__ccache_cached_%s'%(self.proxy), z3.IntSort(), z3.BoolSort())
        # Time when cached
        self.ctime = z3.Function('__ccache_ctime_%s'%(self.proxy), z3.IntSort(), z3.IntSort())
        # Response packet
        self.cresp = z3.Function('__ccache_cresp_%s'%(self.proxy), z3.IntSort(), z3.IntSort())
        # ??
        self.corigbody = z3.Function('__ccache_corigbody_%s'%(self.proxy), z3.IntSort(), z3.IntSort())
        # Packet origin
        self.corigin = z3.Function('__ccache_corigin_%s'%(self.proxy), z3.IntSort(), self.ctx.node)
        #??
        self.crespacket = z3.Function('__ccache_crespacket_%s'%(self.proxy), z3.IntSort(), self.ctx.packet)
        self.creqpacket = z3.Function('__ccache_creqpacket_%s'%(self.proxy), z3.IntSort(), self.ctx.packet)
        self.creqopacket = z3.Function('__ccache_creqopacket_%s'%(self.proxy), z3.IntSort(), self.ctx.packet)
        a1 = z3.Const('__ccachefunc_cache_addr_%s'%(self.proxy), self.ctx.address)
        i1 = z3.Const('__ccachefunc_cache_id_%s'%(self.proxy), z3.IntSort())
