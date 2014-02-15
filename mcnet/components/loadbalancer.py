from . import NetworkObject
import z3
class LoadBalancer (NetworkObject):
    """As opposed to balancing between servers, this load balancer just balances between paths. This both makes it
    simpler and perhaps more interesting. Who knows"""
    def _init (self, balancer, net, context):
        self.ctx = context
        self.balancer = balancer.z3Node
        self.net = net
        self.constraints = list()
        self.net.SaneSend (self, self.constraints)
        self._populateLoadBalancerConstraints()

    @property
    def z3Node (self):
        return self.balancer

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _populateLoadBalancerConstraints (self):
        self.hash_function = z3.Function ('load_balancer_hash_%s'%(self.balancer), self.ctx.port_sort, self.ctx.port_sort, z3.IntSort ())
        p0 = z3.Const('_load_balancer_p0_%s'%(self.balancer), self.ctx.packet)
        p1 = z3.Const('_load_balancer_p1_%s'%(self.balancer), self.ctx.packet)
        n0 = z3.Const('_load_balancer_n0_%s'%(self.balancer), self.ctx.node)
        n1 = z3.Const('_load_balancer_n1_%s'%(self.balancer), self.ctx.node)
        n2 = z3.Const('_load_balancer_n2_%s'%(self.balancer), self.ctx.node)
        hash_same = [self.ctx.packet.src(p0) == self.ctx.packet.src(p1), \
                     self.ctx.packet.dest(p0) == self.ctx.packet.dest(p1), \
                     self.hash_function(self.ctx.src_port(p0), self.ctx.dest_port(p0)) == \
                        self.hash_function(self.ctx.src_port(p1), self.ctx.dest_port(p1)), \
                     self.ctx.send(self.balancer, n0, p0), \
                     self.ctx.send(self.balancer, n1, p1)
                    ]
        self.constraints.append(z3.ForAll([n0, p0, n1, p1], \
                                z3.Implies(z3.And(hash_same), \
                                            n0 == n1)))

        self.constraints.append(z3.ForAll([n0, p0], \
                                  z3.Implies(\
                                      self.ctx.send(self.balancer, n0, p0), \
                                    z3.And( \
                                        z3.Exists([n1], \
                                          z3.And(self.ctx.recv(n1, self.balancer, p0), \
                                            n1 != n0)), \
                                          z3.Not(z3.Exists([n2], \
                                              z3.And(n2 != n0, \
                                                self.ctx.send(self.balancer, n2, p0)))), \
                                          self.ctx.etime(self.balancer, p0, self.ctx.send_event) > \
                                            self.ctx.etime(self.balancer, p0, self.ctx.recv_event)))))
