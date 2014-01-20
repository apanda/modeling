from . import NetworkObject, Core
import z3
class HTTPFirewall (NetworkObject):
    """A layer 7 HTTP firewall: this looks at origin to decide whether to drop the packet or not (assuming flow state hasn't previously been established)"""
    def _init (self, node, network, context):
        self.constraints = list ()
        self.fw = node.z3Node
        self.ctx = context
        network.SaneSend(self)
        self._firewallSendRules ()
        self.acls = []

    def _addConstraints (self, solver):
        solver.add(self.constraints)
        if len(self.acls) == 0:
            return
        p = z3.Const('__firewall_Packet_%s'%(self.fw), self.ctx.packet)
        eh = z3.Const('__firewall_node1_%s'%(self.fw), self.ctx.node)
        aclConstraints = map(lambda (a, b): z3.And(self.ctx.hostHasAddr(self.ctx.packet.origin(p), a), \
                                              self.ctx.packet.dest(p) == b), \
                                              self.acls)
        # Actually enforce firewall rules
        # Actually enforce firewall rules
        # \forall e_1, p send(f, e_1, p) \Rightarrow cached(p.src, p.dest) \lor cached(p.dest, p.src) \lor \neg(ACL(p))
        solver.add(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.fw, eh, p),
                    z3.Not(z3.Or(aclConstraints)))))
    @property
    def z3Node (self):
        return self.fw

    def SetPolicy (self, policy):
        """Wrap add acls"""
        self.AddAcls(policy)

    def AddAcls(self, acls):
        """ACLs as always are in the form (address, address)"""
        if not isinstance(acls, list):
            acls = [acls]
        self.acls.extend(acls)

    @property
    def ACLs (self):
        return self.acls

    def _firewallSendRules (self):

        p = z3.Const('__firewall_Packet_%s'%(self.fw), self.ctx.packet)
        eh = z3.Const('__firewall_node1_%s'%(self.fw), self.ctx.node)
        eh2 = z3.Const('__firewall_node2_%s'%(self.fw), self.ctx.node)
        eh3 = z3.Const('__firewall_node3_%s'%(self.fw), self.ctx.node)

        # The firewall never invents self.ctx.packets
        # \forall e_1, p\ send (f, e_1, p) \Rightarrow \exists e_2 recv(e_2, f, p)
        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.fw, eh, p), \
                                 z3.And(z3.Exists([eh2], self.ctx.recv(eh2, self.fw, p)), \
                                        z3.Not(z3.Exists([eh3], z3.And(self.ctx.send(self.fw, eh3, p),\
                                                                        eh3 != eh))), \
                                        self.ctx.etime(self.fw, p, self.ctx.send_event) >\
                                        self.ctx.etime(self.fw, p, self.ctx.recv_event)))))
