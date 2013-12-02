# Class for network functionality
from . import *
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

    def AdjacencyMap (self, adjGraph):
        for node, adjacent in adjGraph:
            self._adjacencyConstraint(node, adjacent)

    def _adjacencyConstraint (self, nodes, adj):
        if not isinstance(nodes, list):
            nodes = [nodes]
        if not isinstance(adj, list):
            adj = [adj]
        for node in nodes:
            node = node.z3Node
            eh = z3.Const('__adjacency_node_%s'%(node), self.ctx.node)
            p = z3.Const('__adjacency_packet_%s'%(node), self.ctx.packet)
            if len(adj) != 0:
                adjacency_constraint = z3.Or(map(lambda n: eh == n.z3Node, adj))
                # \forall e_1, p recv(e_1, h, p) \Rightarrow \exists e_2 \in Adj: e_1 = e_2
                # \forall e_1, p send(h, e_1, p) \Rightarrow \exists e_2 \in Adj: e_1 = e_2
                self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.recv(eh, node, p), \
                                            adjacency_constraint)))
                self.constraints.append(z3.ForAll([eh, p], z3.Implies(self.ctx.send(node, eh, p), \
                                            adjacency_constraint)))
            else:
                self.constraints.append(z3.ForAll([eh, p], z3.Not(self.ctx.recv(eh, node, p))))
                self.constraints.append(z3.ForAll([eh, p], z3.Not(self.ctx.send(node, eh, p))))

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
            # addrToHost(h) = a_h
            # \forall a \in address, hostHasAddr(h, a) \iff a = a_h
            if not isinstance(addr, list) or len(addr) == 0:
                self.constraints.append(self.ctx.addrToHost(addr) == host.z3Node)
                self.constraints.append(z3.ForAll([tempAddr], \
                            self.ctx.hostHasAddr(host.z3Node, tempAddr) == (tempAddr == \
                                            addr)))
            else:
                addr_clause = z3.Or(map(lambda a: tempAddr == a,  addr))
                self.constraints.append(z3.ForAll([tempAddr], \
                        z3.Implies(self.ctx.hostHasAddr(host.z3Node, tempAddr), \
                                            addr_clause)))
                self.constraints.append(self.ctx.addrToHost(addr[0]) ==\
                                    host.z3Node)

    def RoutingTable (self, node, routing_table):
        """ Routing entries are of the form address -> node"""
        p = z3.Const('__packet__Routing_%s'%(node), self.ctx.packet)
        eh = z3.Const('__node__Routing_%s'%(node), self.ctx.node)
        node = node.z3Node
        for entry in routing_table:
            # \forall p: send(n, e[1], p) \iff p.dest == e[0]
            self.constraints.append(z3.ForAll([eh, p], z3.Implies(z3.And(self.ctx.send(node, eh, p),
                                               (self.ctx.packet.dest(p) == entry[0])), 
                                               eh == entry[1].z3Node)))
