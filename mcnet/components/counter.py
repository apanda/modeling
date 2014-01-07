from . import NetworkObject
import z3
class NetworkCounter (NetworkObject):
    """OK cannot count: this is sad"""
    def _init (self, node, net, ctx):
        self.node = node.z3Node
        self.net = net
        self.ctx = ctx
        self.constraints = list()
        self._constraints ()
        self.net.SaneSend(self)

    @property
    def z3Node (self):
        return self.node

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _constraints (self):
        #self.count_func = z3.Function('count_%s'%(self.node), self.ctx.address, self.ctx.address, \
                                    #z3.IntSort(), z3.IntSort())
        p0 = z3.Const('_counter_p0_%s'%(self.node), self.ctx.packet)
        p1 = z3.Const('_counter_p1_%s'%(self.node), self.ctx.packet)
        n0 = z3.Const('_counter_n0_%s'%(self.node), self.ctx.node)
        n1 = z3.Const('_counter_n1_%s'%(self.node), self.ctx.node)
        n2 = z3.Const('_counter_n2_%s'%(self.node), self.ctx.node)
        t0 = z3.Int('_counter_t0_%s'%(self.node))
        t1 = z3.Int('_counter_t1_%s'%(self.node))
        a0 = z3.Const('_counter_a0_%s'%(self.node), self.ctx.address)
        a1 = z3.Const('_counter_a1_%s'%(self.node), self.ctx.address)

        # Make sure all packets sent were first recved
        self.constraints.append(z3.ForAll([n0, p0], \
                              z3.Implies(self.ctx.send(self.node, n0, p0), \
                                z3.And( \
                                    z3.Exists([n1], \
                                      z3.And (self.ctx.recv(n1, self.node, p0), \
                                       n0 != n1)), \
                                       z3.Not(z3.Exists([n2], \
                                              z3.And(self.ctx.send(self.node, n2, p0), \
                                                     n2 != n0))), \
                                       self.ctx.etime(self.node, p0, self.ctx.send_event) > \
                                           self.ctx.etime(self.node, p0, self.ctx.recv_event)))))

        # Make sure packets go one at a time
        self.constraints.append(z3.ForAll([p0, t0], \
                              z3.Implies(z3.And(self.ctx.etime(self.node, p0, self.ctx.send_event) == t0, \
                                               t0 != 0), \
                                           z3.ForAll([p1], \
                                                z3.Or(p0 == p1, \
                                                   self.ctx.etime(self.node, p1, \
                                                                 self.ctx.send_event) != \
                                                       t0)))))

        # TODO: Figure out if this needs to be implemented.
        #self.constraints.append(z3.ForAll([a0, a1],
                                #self.count_func(a0, a1, 0) == 0))

        #self.constraints.append(z3.ForAll([p0, t0], \
                              #z3.Implies(z3.And(self.ctx.etime(self.node, p0, self.ctx.send_event) == t0, \
                                                #t0 > 0), \
                                 #self.count_func(self.ctx.packet.src(p0), self.ctx.packet.dest(p0), t0) ==
                                    #self.count_func(self.ctx.packet.src(p0), self.ctx.packet.dest(p0), t0 - 1) + 1)))

        #self.constraints.append(z3.ForAll([a0, a1, t0], \
                                #z3.Implies( \
                                  #z3.Not(z3.Exists([p0], \
                                    #z3.And(self.ctx.etime(self.node, p0, self.ctx.send_event) == t0, \
                                           #self.ctx.packet.src(p0) == a0, \
                                           #self.ctx.packet.dest(p0) == a1))), \
                                    #self.count_func(a0, a1, t0) == self.count_func(a0, a1, t0 - 1))))
