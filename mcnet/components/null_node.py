from . import NetworkObject
import z3
class NullNode (NetworkObject):
    def _init (self, node, net, ctx):
        self.net = net
        self.ctx = ctx
        self.node = node.z3Node
        self.constraints = list ()
        self.net.SaneSend (self, self.constraints)
        self._nullNode ()
    
    @property
    def z3Node (self):
        return self.node

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _nullNode (self): 
        p = z3.Const('__nnode_Packet_%s'%(self.node), self.ctx.packet)
        n0 = z3.Const('__nnode_node1_%s'%(self.node), self.ctx.node)
        n2 = z3.Const('__nnode_node2_%s'%(self.node), self.ctx.node)
        n3 = z3.Const('__nnode_node3_%s'%(self.node), self.ctx.node)
        # The nnode never invents self.ctx.packets
        # \forall e_1, p\ send (f, e_1, p) \Rightarrow \exists e_2 recv(e_2, f, p)
        self.constraints.append(z3.ForAll([n0, p], z3.Implies(self.ctx.send(self.node, n0, p), \
                                 z3.And(z3.Exists([n2], self.ctx.recv(n2, self.node, p)), \
                                        z3.Not(z3.Exists([n3], z3.And(self.ctx.send(self.node, n3, p),\
                                                                        n3 != n0))), \
                                        self.ctx.etime(self.node, p, self.ctx.send_event) >\
                                        self.ctx.etime(self.node, p, self.ctx.recv_event)))))
