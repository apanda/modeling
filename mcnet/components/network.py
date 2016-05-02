# Class for network functionality
from . import Core, destAddrPredicate, NetworkObject
import z3
import collections
from collections import defaultdict
class Network (Core):
    """Model for a network, encompasses routing and wiring"""
    def _init(self,  context):
        self.ctx = context
        self.constraints = list()
        self.elements = list()

    def Attach (self, *elements):
        self.elements.extend(elements)

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def setAddressMappings (self, addrmap):
        """Specify host to address mapping"""
        # Set address mapping for nodes.
        for node, addr in addrmap:
            a_0 = z3.Const('%s_address_mapping_a_0'%(node), self.ctx.address)
            # Node has a single address
            if not isinstance(addr, list) or len(addr) == 0:
                # $$addrToNode(addr) = node$$
                self.constraints.append(self.ctx.addrToNode(addr) == node.z3Node)
                # $$nodeHasAddr(node, a_0) \iff a_0 = addr$$
                # Note we need the $\iff$ here to make sure that we set nodeHasAddr to false
                # for other addresses.
                self.constraints.append(z3.ForAll([a_0], \
                    (a_0 == addr) == self.ctx.nodeHasAddr(node.z3Node, a_0)))
            # Node has several addresses
            else:
                or_clause = []
                for ad in addr:
                    # $$addrToNode(addr) = node$$
                    self.constraints.append(self.ctx.addrToNode(ad) == node.z3Node)
                    or_clause.append(a_0 == ad)
                # Note we need the $\iff$ here to make sure that we set nodeHasAddr to false
                # for other addresses.
                self.constraints.append(z3.ForAll([a_0], \
                        z3.Or(or_clause) == self.ctx.nodeHasAddr(node.z3Node, a_0)))

    def SaneSend (self, node):
        """Don't forward packets addressed to node"""
        # SaneSend(self, node): Don't forward packets addressed to the node.
        n_0 = z3.Const('%s_saneSend_n_0'%(node), self.ctx.node)
        p_0 = z3.Const('%s_saneSend_p_0'%(node), self.ctx.packet)
        t_0 = z3.Int('%s_saneSend_t_0'%(node))
        # Constant: node
        # $$send(node, n_0, p, t_0) \Rightarrow \lneg nodeHasAddr(node, p.dest)$$
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
                z3.Implies(self.ctx.send(node.z3Node, n_0, p_0, t_0), \
                                  z3.Not(self.ctx.nodeHasAddr(node.z3Node, self.ctx.packet.dest(p_0))))))

    def SetGateway (self, node, gateway):
        """Node sends all traffic through gateway"""
        # SetGateway(self, node, gateway): All packets from node are sent through gateway
        n_0 = z3.Const('%s_gateway_n_0'%(node), self.ctx.node)
        p_0 = z3.Const('%s_gateway_p_0'%(node), self.ctx.packet)
        t_0 = z3.Int('%s_gateway_t_0'%(node))
        # $$send(node, n_0, p_0, t_0) \Rightarrow n_0 = gateway$$
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
            z3.Implies(self.ctx.send(node.z3Node, n_0, p_0, t_0), \
                                            n_0 == gateway.z3Node)))
        #self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
            #z3.Implies(self.ctx.recv(n_0, node.z3Node,  p_0, t_0), \
                                            #n_0 == gateway.z3Node)))
    def DisallowAddresses (self, addresses):
        """Disallow sending to certain addresses"""
        n_0 = z3.Const('disallow_n_0', self.ctx.node)
        n_1 = z3.Const('disallow_n_1', self.ctx.node)
        t_0 = z3.Int('disallow_t_0')
        p_0 = z3.Const('disallow_pkt', self.ctx.packet)
        constraints = map(lambda a: self.ctx.packet.dest(p_0) == a, addresses)
        constraints += map(lambda a: self.ctx.packet.src(p_0) == a, addresses)
        self.constraints.append(z3.ForAll([n_0, n_1, t_0, p_0], \
                z3.Implies(self.ctx.send(n_0, n_1, p_0, t_0), z3.Not(z3.Or(constraints)))))

    def RoutingTable (self, node, routing_table):
        """ Routing entries are of the form address -> node"""
        compositionPolicy = map(lambda (d, n): (destAddrPredicate(self.ctx, d), n), routing_table)
        self.CompositionPolicy(node, compositionPolicy)

    def RoutingTableWithFailure (self, node, routing_table):
        """Routing table is (address, failure, predicate, node)"""
        def fail_predicate(d, f):
            return lambda p, t: z3.And(destAddrPredicate(self.ctx, d)(p), f(t))
        composition_policy = map(lambda (d, f, n): (fail_predicate(d, f), n), routing_table)
        self.CompositionPolicyWithFailure(node, composition_policy)

    def SourceRoutingTableWithFailure(self, node, routing_table):
        """Routing table is (dest, source, failure, predicate, node)"""
        def source_fail_predicate(d, s, f):
            def predicate_func(p, t):
                t_0 = z3.Int('route_t')
                t_1 = z3.Int('route_t1')
                n = z3.Const('%s_route_n', self.ctx.node)
                received = z3.Exists([t_0], z3.And(self.ctx.recv(s.z3Node, node.z3Node, p, t_0), \
                                                    t_0 < t, \
                                                    z3.ForAll([t_1, n], \
                                                      z3.Or(t_1 > t, \
                                                      z3.Implies(self.ctx.recv(n, node.z3Node, p, t_1), \
                                                         z3.Or(t_1 < t_0, z3.And(t_1 == t_0, n == s.z3Node)))))))
                return z3.And(destAddrPredicate(self.ctx, d)(p), f(t), received)
            return predicate_func
        composition_policy = map(lambda (d, s, f, n): (source_fail_predicate(d, s, f), n), routing_table)
        self.CompositionPolicyWithFailure(node, composition_policy)

    def SourceRoutingTable(self, node, routing_table):
        """Routing table is (dest, source, node)"""
        def source_predicate(d, s):
            def predicate(p, t):
                t_0 = z3.Int('route_t')
                t_1 = z3.Int('route_t1')
                n = z3.Const('%s_route_n', self.ctx.node)
                received = z3.Exists([t_0], z3.And(self.ctx.recv(s.z3Node, node.z3Node, p, t_0), \
                                                    t_0 < t, \
                                                    z3.ForAll([t_1, n], \
                                                      z3.Or(t_1 > t, \
                                                      z3.Implies(self.ctx.recv(n, node.z3Node, p, t_1), \
                                                         z3.Or(t_1 < t_0, z3.And(t_1 == t_0, n == s.z3Node)))))))
                return z3.And(destAddrPredicate(self.ctx, d)(p), received)
            return predicate
        composition_policy = map(lambda (d,s, n): (source_predicate(d, s), n), routing_table)        
        self.CompositionPolicyWithFailure(node, composition_policy)

    def CompositionPolicyWithFailure (self, node, policy):
        """ Composition policies steer packets between middleboxes.
            Policy is of the form predicate -> node"""
        p_0 = z3.Const('%s_composition_p_0'%(node), self.ctx.packet)
        n_0 = z3.Const('%s_composition_n_0'%(node), self.ctx.node)
        t_0 = z3.Int('%s_composition_t_0'%(node))
        collected = defaultdict(list)
        node_dict = {}
        for (predicate, dnode) in policy:
            collected[str(dnode)].append(predicate)
            node_dict[str(dnode)] = dnode
        for nk, predicates in collected.iteritems():
            dnode = node_dict[nk]
            predicates = z3.Or(map(lambda p: p(p_0, t_0), predicates))
            self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
                    z3.Implies(z3.And(self.ctx.send(node.z3Node, n_0, p_0, t_0), predicates), \
                                n_0 == dnode.z3Node)))

    def CompositionPolicy (self, node, policy):
        """ Composition policies steer packets between middleboxes.
            Policy is of the form predicate -> node"""
        p_0 = z3.Const('%s_composition_p_0'%(node), self.ctx.packet)
        n_0 = z3.Const('%s_composition_n_0'%(node), self.ctx.node)
        t_0 = z3.Int('%s_composition_t_0'%(node))
        collected = defaultdict(list)
        node_dict = {}
        for (predicate, dnode) in policy:
            collected[str(dnode)].append(predicate)
            node_dict[str(dnode)] = dnode
        for nk, predicates in collected.iteritems():
            dnode = node_dict[nk]
            predicates = z3.Or(map(lambda p: p(p_0), predicates))
            self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
                    z3.Implies(z3.And(self.ctx.send(node.z3Node, n_0, p_0, t_0), predicates), \
                                n_0 == dnode.z3Node)))

    def RoutingTableShunt (self, node, routing_table, shunt_node):
        """ Routing entries are of the form address -> node. Also allows packet to be sent to another
        box for further processing"""
        compositionPolicy = map(lambda (d, n): (destAddrPredicate(self.ctx, d), n), routing_table)
        self.CompositionPolicyShunt(node, compositionPolicy, shunt_node)

    def CompositionPolicyShunt (self, node, policy, shunt_node):
        """ Composition policies steer packets between middleboxes.
            Policy is of the form predicate -> node"""
        p_0 = z3.Const('%s_composition_p_0'%(node), self.ctx.packet)
        n_0 = z3.Const('%s_composition_n_0'%(node), self.ctx.node)
        t_0 = z3.Int('%s_composition_t_0'%(node))
        collected = defaultdict(list)
        node_dict = {}
        for (predicate, dnode) in policy:
            collected[str(dnode)].append(predicate)
            node_dict[str(dnode)] = dnode
        for nk, predicates in collected.iteritems():
            dnode = node_dict[nk]
            predicates = z3.Or(map(lambda p: p(p_0), predicates))
            self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
                    z3.Implies(z3.And(self.ctx.send(node.z3Node, n_0, p_0, t_0), predicates), \
                                z3.Or(n_0 == dnode.z3Node, n_0 == shunt_node.z3Node))))

    #def SimpleIsolation (self, node, addresses):
        #p = z3.Const('%s_s_p'%(node), self.ctx.packet)
        #n = z3.Const('%s_s_n'%(node), self.ctx.node)
        #t = z3.Int('%s_s_t'%(node))
        #a_pred = map(lambda a: z3.Or(self.ctx.packet.src(p) == a, \
                                     #self.ctx.packet.dest(p) == a), \
                        #addresses)
        #self.constraints.append(\
                #z3.ForAll([p, n, t], \
                  #z3.Implies(self.ctx.recv(n, node.z3Node, p, t), \
                            #z3.Or(a_pred))))
        #self.constraints.append(\
                #z3.ForAll([p, n, t], \
                  #z3.Implies(self.ctx.send(node.z3Node, n, p, t), \
                            #z3.Or(a_pred))))

    def SetIsolationConstraint (self, node,  adjacencies):
        """Set isolation constraints on a node. Doesn't need to be set but
        useful when interfering policies are in play."""

        n_0 = z3.Const('%s_isolation_n_0'%(node), self.ctx.node)
        p_0 = z3.Const('%s_isolation_p_0'%(node), self.ctx.packet)
        t_0 = z3.Int('%s_isolation_t_0'%(node))
        if not isinstance(adjacencies, list):
            adjacencies = [adjacencies]
        node = node.z3Node
        adjacencies = map(lambda a: a.z3Node if isinstance(a, NetworkObject) \
                                         else a, adjacencies)
        clause = z3.Or(map(lambda a: n_0 == a, adjacencies))

        self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
            z3.Implies(self.ctx.send(node, n_0, p_0, t_0), \
                                    clause)))
        self.constraints.append(z3.ForAll([n_0, p_0, t_0], \
            z3.Implies(self.ctx.recv(n_0, node, p_0, t_0), \
                                    clause))) 
    @property
    def EndHosts (self):
        """Return all currently attached endhosts"""
        return {str(el.z3Node) : el for el in filter(lambda e: e.isEndHost, self.elements)}

