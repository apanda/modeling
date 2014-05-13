from . import NetworkObject, Core
import z3
class DpiFW (NetworkObject):
    """ Intrusion prevention system: Just combines a stateful fw with DPI, hooray"""
    def _init (self, policy, node, network, context):
        """Policy is an object of type dpi_policy"""
        self.constraints = list ()
        self.policy = policy
        self.ips = node.z3Node
        self.ctx = context
        network.SaneSend(self, self.constraints)
        self._ipsSendRules ()
        self.acls = []

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    @property
    def z3Node (self):
        return self.ips

    def _ipsSendRules (self):
        p = z3.Const('__ips_Packet_%s'%(self.ips), self.ctx.packet)
        eh = z3.Const('__ips_node1_%s'%(self.ips), self.ctx.node)
        eh2 = z3.Const('__ips_node2_%s'%(self.ips), self.ctx.node)
        eh3 = z3.Const('__ips_node3_%s'%(self.ips), self.ctx.node)

        # The ips never invents packets
        # \forall e_1, p\ send (f, e_1, p) \Rightarrow \exists e_2 recv(e_2, f, p)
        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.ips, eh, p), \
                z3.Exists([eh2], \
                 z3.And(self.ctx.recv(eh2, self.ips, p), \
                    z3.Not(z3.Exists([eh3], z3.And(self.ctx.send(self.ips, eh3, p),\
                                                   eh3 != eh))), \
                    self.ctx.etime(self.ips, p, self.ctx.recv_event) < \
                        self.ctx.etime(self.ips, p, self.ctx.send_event))))))

        # Actually enforce ips rules
        # \forall e_1, p send(f, e_1, p) \Rightarrow (cached(p.src, p.dest)
        #                       \land ctime(p.src, p.dest) <= etime(ips, p, R))
        #                       \lor (cached(p.dest, p.src) \land ctime(p.dest, p.src) <= etime(ips. p, R))
        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(self.ips, eh, p), \
          z3.Not(self.policy.dpi_match(self.ctx.packet.body(p))))))
        self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.recv(eh, self.ips, p), \
          z3.Or(z3.Exists([eh2], self.ctx.send(self.ips, eh2, p)), \
             self.policy.dpi_match(self.ctx.packet.body(p))))))
