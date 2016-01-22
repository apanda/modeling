from . import NetworkObject
import z3

class ContentCache (NetworkObject):
    """A caching web proxy"""
    def _init (self, node, network, context):
        super(ContentCache, self).init_fail(node)
        self.proxy = node.z3Node
        self.ctx = context
        self.constraints = list ()
        network.SaneSend(self)
        self._constraints()

    @property
    def z3Node (self):
        return self.proxy

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _constraints(self):
        n_0 = z3.Const('%s_cc_n_0'%(self.proxy), self.ctx.node)
        n_1 = z3.Const('%s_cc_n_1'%(self.proxy), self.ctx.node)
        p_0 = z3.Const('%s_cc_p_0'%(self.proxy), self.ctx.packet)
        p_1 = z3.Const('%s_cc_p_1'%(self.proxy), self.ctx.packet)
        t_0 = z3.Int('%s_cc_t_0'%(self.proxy))
        t_1 = z3.Int('%s_cc_t_1'%(self.proxy))
        t_2 = z3.Int('%s_cc_t_2'%(self.proxy))
        b_0 = z3.Int('%s_cc_b_0'%(self.proxy))
        self.cached = z3.Function('%s_cached'%(self.proxy), z3.IntSort(), z3.IntSort(), z3.BoolSort())
        self.cached_origin = z3.Function('%s_cached_origin'%(self.proxy), z3.IntSort(), z3.IntSort(), self.ctx.node)
        self.cached_body = z3.Function('%s_cached_body'%(self.proxy), z3.IntSort(), z3.IntSort(), z3.IntSort())
        self.cached_obody = z3.Function('%s_cached_obody'%(self.proxy), z3.IntSort(), z3.IntSort(), z3.IntSort())
        
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
             z3.Implies(self.ctx.send(self.proxy, n_0, p_0, t_0), \
               self.ctx.nodeHasAddr(self.proxy, self.ctx.packet.src(p_0)))))
       
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
            z3.Implies(self.ctx.send(self.proxy, n_0, p_0, t_0), \
              z3.Exists([n_1, p_1, t_1], \
                z3.And(self.ctx.recv(n_1, self.proxy, p_1, t_1), \
                       t_1 < t_0, \
                       z3.Or(
                         z3.And(self.ctx.packet.body(p_1) == self.ctx.packet.body(p_0), \
                                self.ctx.packet.origin(p_1) == self.ctx.packet.origin(p_0), \
                                self.ctx.packet.orig_body(p_1) == self.ctx.packet.orig_body(p_0), \
                                self.ctx.dest_port(p_1) == self.ctx.dest_port(p_0), \
                                self.ctx.packet.dest(p_1) == self.ctx.packet.dest(p_0)), \
                         z3.And(self.cached(self.ctx.packet.body(p_1), t_1), \
                                self.ctx.packet.origin(p_0) == \
                                    self.cached_origin(self.ctx.packet.body(p_1), t_1), \
                                self.ctx.packet.orig_body(p_0) == \
                                    self.cached_obody(self.ctx.packet.body(p_1), t_1), \
                                self.ctx.packet.dest(p_0) == self.ctx.packet.src(p_1), \
                                self.ctx.dest_port(p_0) == self.ctx.src_port(p_1), \
                                self.ctx.src_port(p_0) == self.ctx.dest_port(p_1))))))))

        self.constraints.append(z3.ForAll([b_0, t_0], \
            z3.Implies(self.cached(b_0, t_0), 
              z3.Exists([n_0, p_0, t_1], \
                z3.And(self.ctx.send(self.proxy, n_0, p_0, t_1), \
                   self.ctx.packet.body(p_0) == b_0, \
                   t_1 < t_0, \
                   z3.Exists([n_1, p_1, t_2], \
                   z3.And(self.ctx.recv(n_1, self.proxy, p_1, t_2), \
                     t_2 > t_1, \
                     t_2 < t_0, \
                     self.ctx.packet.dest(p_1) == self.ctx.packet.src(p_0), \
                     self.ctx.packet.src(p_1) == self.ctx.packet.dest(p_0), \
                     self.ctx.src_port(p_1) == self.ctx.dest_port(p_0), \
                     self.ctx.dest_port(p_1) == self.ctx.src_port(p_0), \
                     self.cached_body(b_0, t_0) == self.ctx.packet.body(p_1), \
                     self.cached_origin(b_0, t_0) == self.ctx.packet.origin(p_1), \
                     self.cached_obody(b_0, t_0) == self.ctx.packet.orig_body(p_1))))))))
