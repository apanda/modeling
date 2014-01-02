from . import NetworkObject
import z3
class WanOptimizer (NetworkObject):
    def _init(self, transformation, node, network, context):
        self.opt = node
        self.ctx = context
        self.constraints = list ()
        self.transformation = transformation
        network.SaneSend (self)
        self._wanOptSendRule ()

    @property
    def z3Node (self):
        return self.opt

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _wanOptSendRule (self):
        p1 = z3.Const('__wanopt_unmoded_packet_%s'%(self.opt), self.ctx.packet)
        p2 = z3.Const('__wanopt_moded_packet_%s'%(self.opt), self.ctx.packet)
        e1 = z3.Const('__wanopt_ingress_node_%s'%(self.opt), self.ctx.node)
        e2 = z3.Const('__wanopt_egress_node_%s'%(self.opt), self.ctx.node)
        e3 = z3.Const('__wanopt_not_egress_node_%s'%(self.opt), self.ctx.node)

        self.constraints.append( \
                z3.ForAll([e1, p1], \
                    z3.Implies(self.ctx.send(self.opt, e1, p1), \
                        z3.Exists([e2, p2], \
                           z3.And(self.ctx.recv(e2, self.opt, p2), \
                            self.ctx.PacketsHeadersEqual(p1, p2), \
                            self.ctx.packet.body(p1) == self.transformation(self.ctx.packet.body(p2)), \
                            z3.Not(z3.Exists([e3], \
                                z3.And(e3 != e1, \
                                    self.ctx.send(self.opt, e3, p2)))), \
                            self.ctx.etime(self.opt, p1, self.ctx.send_event) > \
                                self.ctx.etime(self.opt, p2, self.ctx.recv_event))))))

        #self.constraints.append( \
                #z3.ForAll([e2, p2], \
                    #z3.Implies(self.ctx.recv(e2, self.opt, p2), \
                        #z3.Exists([e1, p1], \
                           #z3.And(self.ctx.send(self.opt, e1, p1), \
                            #self.ctx.PacketsHeadersEqual(p1, p2), \
                            #self.ctx.packet.body(p1) == self.transformation(self.ctx.packet.body(p2)), \
                            #z3.Not(z3.Exists([e3], \
                                #z3.And(e3 != e1, \
                                    #self.ctx.send(self.opt, e3, p2)))), \
                            #self.ctx.etime(self.opt, p1, self.ctx.send_event) > \
                                #self.ctx.etime(self.opt, p2, self.ctx.recv_event))))))
