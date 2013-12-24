# Class for network functionality
from . import Core, destAddrPredicate, NetworkObject
import z3
class Network (Core):
    """Represent a network, this encompases both routing and wiring"""
    def _init(self,  context):
        self.ctx = context
        self.constraints = list()
        self.elements = list()

    def Attach (self, *elements):
        self.elements.extend(elements)

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def SaneSend (self, node):
        eh = z3.Const('__saneSend_eh_%s'%(node), self.ctx.node)
        p = z3.Const('__saneSend_p_%s'%(node), self.ctx.packet)
        # Don't send packets meant for node
        # \forall e, p:\ send (f, e, p) \Rightarow \neg hostHasAddr (f, p.dest)
        self.constraints.append(z3.ForAll([eh, p], \
            z3.Implies(self.ctx.send(node.z3Node, eh, p), \
                z3.Not(self.ctx.hostHasAddr(node.z3Node, self.ctx.packet.dest(p))))))

    def setAddressMappings (self, addrmap):
        """Constraints to ensure that a host has only the addresses in the map"""
        tempAddr = z3.Const("__setAdMapExclusive_address", self.ctx.address)
        for host, addr in addrmap:
            if isinstance(host, NetworkObject):
                host = host.z3Node
            # addrToHost(h) = a_h
            # \forall a \in address, hostHasAddr(h, a) \iff a = a_h
            if not isinstance(addr, list) or len(addr) == 0:
                self.constraints.append(self.ctx.addrToHost(addr) == host)
                self.constraints.append(z3.ForAll([tempAddr], \
                            self.ctx.hostHasAddr(host, tempAddr) == (tempAddr == \
                                            addr)))
            else:
                addr_clause = z3.Or(map(lambda a: tempAddr == a,  addr))
                self.constraints.append(z3.ForAll([tempAddr], \
                        z3.Implies(self.ctx.hostHasAddr(host, tempAddr), \
                                            addr_clause)))
                self.constraints.append(self.ctx.addrToHost(addr[0]) ==\
                                    host)

    def RoutingTable (self, node, routing_table):
        """ Routing entries are of the form address -> node"""
        compositionPolicy = map(lambda (d, n): (destAddrPredicate(self.ctx, d), n), routing_table)
        self.CompositionPolicy(node, compositionPolicy)

    def CompositionPolicy (self, node, policy):
        """ Composition policies steer packets between middleboxes.
            Policy is of the form predicate -> node"""
        p = z3.Const('__packet__Routing_%s'%(node), self.ctx.packet)
        eh = z3.Const('__node__Routing_%s'%(node), self.ctx.node)
        node = node.z3Node
        for (predicate, dnode) in policy:
            # The implication in this direction allows for the existence of things like firewalls
            # that might drop the packet instead of forwarding it.

            # \forall p: send(n, e, p) \land p.dest == e[0] \Rightarrow e == e[1]
            self.constraints.append(z3.ForAll([eh, p], z3.Implies(z3.And(self.ctx.send(node, eh, p),
                                               predicate(p)), 
                                               eh == dnode.z3Node)))

    def SetGateway (self, node, gateway):
        """ Set a node so it sends all packets to gateway"""
        p = z3.Const('__packet__Routing_%s'%(node), self.ctx.packet)
        eh = z3.Const('__node__Routing_%s'%(node), self.ctx.node)
        #self.CompositionPolicy(node, [(lambda p: True, gateway)])
        self.SetIsolationConstraint(node, gateway)
    
    def SetIsolationConstraint (self, node,  adjacencies):
        """Set isolation constraints on a node. Doesn't need to be set but
        useful when interfering policies are in play."""

        if not isinstance(adjacencies, list):
            adjacencies = [adjacencies]
        node = node.z3Node
        n = z3.Const ('__node_Isolation_%s'%(node), self.ctx.node)
        p = z3.Const ('__pkt_Isolation_%s'%(node), self.ctx.packet)
        adjacencies = map(lambda a: a.z3Node if isinstance(a, NetworkObject) \
                                         else a, adjacencies)
        clause = z3.Or(map(lambda a: n == a, adjacencies))
        self.constraints.append(z3.ForAll([n, p], \
                                  z3.Implies(self.ctx.send(node, n, p), \
                                             clause)))
        self.constraints.append(z3.ForAll([n, p], \
                                  z3.Implies(self.ctx.recv(n, node, p), \
                                             clause)))

    @property
    def EndHosts (self):
        """Return all currently attached endhosts"""
        return {str(el.z3Node) : el for el in filter(lambda e: e.isEndHost, self.elements)} 
