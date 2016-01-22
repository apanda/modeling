from . import NetworkObject
import z3

class AclContentCache (NetworkObject):
    """A caching web proxy"""
    def _init (self, node, network, context):
        super(AclContentCache, self).init_fail(node)
        self.proxy = node.z3Node
        self.ctx = context
        self.constraints = list ()
        self.acls = []
        network.SaneSend(self)
        self._constraints()

    @property
    def z3Node (self):
        return self.proxy

    def AddAcls(self, acls):
        if not isinstance(acls, list):
            acls = [acls]
        self.acls.extend(acls)

    def _addConstraints (self, solver):
        solver.add(self.constraints)
        self._aclConstraints(solver)

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
        self.cached_src = z3.Function('%s_cached_src'%(self.proxy), z3.IntSort(), z3.IntSort(), self.ctx.address)
        self.acl_func = z3.Function('%s_acl_func'%(self.proxy), self.ctx.address, self.ctx.address, z3.BoolSort())
        
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
                                self.ctx.packet.dest(p_1) == self.ctx.packet.dest(p_0), \
                                self.acl_func(self.ctx.packet.src(p_1), self.ctx.packet.dest(p_1))), \
                         z3.And(self.cached(self.ctx.packet.body(p_1), t_1), \
                                self.ctx.packet.origin(p_0) == \
                                    self.cached_origin(self.ctx.packet.body(p_1), t_1), \
                                self.ctx.packet.orig_body(p_0) == \
                                    self.cached_obody(self.ctx.packet.body(p_1), t_1), \
                                self.ctx.packet.dest(p_0) == self.ctx.packet.src(p_1), \
                                self.ctx.dest_port(p_0) == self.ctx.src_port(p_1), \
                                self.ctx.src_port(p_0) == self.ctx.dest_port(p_1), \
                                self.acl_func(self.cached_src(self.ctx.packet.body(p_1), t_1), \
                                              self.ctx.packet.dest(p_0)))))))))

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
                     self.cached_obody(b_0, t_0) == self.ctx.packet.orig_body(p_1), \
                     self.cached_src(b_0, t_0) == self.ctx.packet.src(p_1))))))))

    def _aclConstraints(self, solver):
        if len(self.acls) == 0:
            return
        a_0 = z3.Const('%s_cc_acl_a_0'%(self.proxy), self.ctx.address)
        a_1 = z3.Const('%s_cc_acl_a_1'%(self.proxy), self.ctx.address)
        acl_map = map(lambda (a, b): z3.And(a_0 == a, a_1 == b), self.acls)
        solver.add(z3.ForAll([a_0, a_1], self.acl_func(a_0, a_1) == z3.Not(z3.Or(acl_map))))
