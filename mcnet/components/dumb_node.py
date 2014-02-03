from . import NetworkObject
import z3
class DumbNode (NetworkObject):
    """This is just a wrapper around z3 instances. The idea is that by using this we perhaps need to have fewer (or no)
    ifs to deal with the case where we don't instantiate an object for a node"""
    def _init (self, node, ctx):
        self.node = node
        self.ctx = ctx

    @property
    def z3Node (self):
        return self.node

    def _addConstraints (self, solver):
        n = z3.Const('__nodeRules_Node', self.ctx.node)
        n2 = z3.Const('__nodeRules_Node2', self.ctx.node)
        n3 = z3.Const('__nodeRules_Node3', self.ctx.node)
        p = z3.Const('__nodeRules_Packet', self.ctx.packet)
        p2 = z3.Const('__nodeRules_Packet2', self.ctx.packet)

        # Appending what sort of packet are sent normally
        solver.append(z3.ForAll([n, p], \
                z3.Implies(self.ctx.send(self.node, n, p), \
                    z3.Or(self.ctx.hostHasAddr(self.node, self.ctx.packet.src(p)), \
                       z3.Exists([n2, p2], z3.And(self.ctx.recv(n2, self.node, p2), \
                                                       self.ctx.PacketsHeadersEqual(p, p2), \
                                                       self.ctx.etime(self.node, p, self.ctx.send_event) > \
                                                        self.ctx.etime(self.node, p2, self.ctx.recv_event)))))))
        # Appending what sort of packet are sent normally
        solver.append(z3.ForAll([n, p], \
                z3.Implies(self.ctx.send(self.node, n, p), \
                    z3.Or(self.ctx.packet.origin(p) == self.node, \
                          z3.Exists([n2, p2], z3.And(self.ctx.recv(n2, self.node, p2), \
                                                   self.ctx.packet.origin(p2) ==\
                                                        self.ctx.packet.origin(p),
                                                    self.ctx.etime(self.node, p, self.ctx.send_event) > \
                                                     self.ctx.etime(self.node, p2, self.ctx.recv_event)))))))
        #solver.append(z3.ForAll([n, n2, p], \
                #z3.Implies(z3.And(self.ctx.send(n, n2, p), \
                        #self.ctx.hostHasAddr(self.node, self.ctx.packet.src(p))), \
                        #z3.And(z3.Exists([n3], \
                            #self.ctx.send(self.node, n3, self.ctx.origPacket(p)))))))
