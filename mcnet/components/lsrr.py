from . import Core, NetworkObject
import z3
class LSRROption (Core):
    """The LSRR field primitive adds support for loose source routing to the model"""
    def _init (self, field_name, context):
        self.name = field_name
        self.ctx = context
        self.constraints = list ()
        self.CreateLSRRField ()

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def CreateLSRRField (self):
        self.LSRROption = z3.Function('lsrr_%s'%(self.name), z3.IntSort(), self.ctx.address, self.ctx.address)
        o0 = z3.Int('option_1_%s'%(self.name))
        o1 = z3.Int('option_2_%s'%(self.name))
        a0 = z3.Const('a0_%s'%(self.name), self.ctx.address)
        a1 = z3.Const('a1_%s'%(self.name), self.ctx.address)
        self.constraints.append(z3.ForAll([a0], \
               self.LSRROption(0, a0) == a0))

class LSRRRouter (NetworkObject):
    """IP router supporting LSRR functions"""
    def _init (self, router, lsrr_option, network, context):
        self.router = router.z3Node
        self.net = network
        self.ctx = context
        self.constraints = list ()
        self.net.SaneSend (self, self.constraints)
        self.option = lsrr_option.LSRROption
        self.LSRRConstraints ()

    def _addConstraints (self, solver):
        solver.add (self.constraints)

    @property
    def z3Node (self):
        return self.router

    def LSRRConstraints (self):
        p0 = z3.Const('_counter_p0_%s'%(self.router), self.ctx.packet)
        p1 = z3.Const('_counter_p1_%s'%(self.router), self.ctx.packet)
        n0 = z3.Const('_counter_n0_%s'%(self.router), self.ctx.node)
        n1 = z3.Const('_counter_n1_%s'%(self.router), self.ctx.node)
        n2 = z3.Const('_counter_n2_%s'%(self.router), self.ctx.node)
        t0 = z3.Int('_counter_t0_%s'%(self.router))
        t1 = z3.Int('_counter_t1_%s'%(self.router))
        a0 = z3.Const('_counter_a0_%s'%(self.router), self.ctx.address)
        a1 = z3.Const('_counter_a1_%s'%(self.router), self.ctx.address)
        self.constraints.append ( \
                z3.ForAll ([p0, n0], \
                    z3.Implies (self.ctx.send(self.router, n0, p0), \
                       z3.Or( \
                          z3.Exists([n1], \
                           z3.And(self.ctx.recv(n1, self.router, p0), \
                             z3.Not(self.ctx.hostHasAddr(self.router, \
                                        self.ctx.packet.dest(p0))), \
                             z3.Not(z3.Exists([n2], \
                                z3.And(n2 != n0, \
                                       self.ctx.send(self.router, n2, p0)))), \
                             self.ctx.etime(self.router, p0, self.ctx.recv_event) < \
                                self.ctx.etime(self.router, p1, self.ctx.send_event))), \
                          z3.Exists([n1, p1], \
                            z3.And(self.ctx.recv(n1, self.router, p1), \
                              self.ctx.hostHasAddr(self.router, self.ctx.packet.dest(p1)), \
                              z3.Not(z3.Exists([n2], \
                                z3.And(n2 != n0, \
                                       self.ctx.send(self.router, n2, p0)))), \
                              self.ctx.hostHasAddr(self.router, \
                                            self.ctx.packet.src(p0)), \
                              self.ctx.packet.dest(p0) == \
                                    self.option(self.ctx.packet.options(p0), \
                                                  self.ctx.packet.dest(p1)), \
                              z3.Not(self.ctx.hostHasAddr(self.router, \
                                                self.ctx.packet.dest(p0))), \
                              self.ctx.src_port(p0) == self.ctx.src_port(p1), \
                              self.ctx.dest_port(p0) == self.ctx.dest_port(p1), \
                              self.ctx.packet.body(p0) == self.ctx.packet.body(p1), \
                              self.ctx.packet.orig_body(p0) == self.ctx.packet.orig_body(p1), \
                              self.ctx.packet.seq(p0) == self.ctx.packet.seq(p1), \
                              self.ctx.packet.options(p0) == self.ctx.packet.options(p1), \
                              self.ctx.packet.origin(p0) == self.ctx.packet.origin(p1), \
                              self.ctx.etime(self.router, p1, self.ctx.recv_event) < \
                                self.ctx.etime(self.router, p0, self.ctx.send_event)))))))

