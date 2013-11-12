import z3
def toSMT2Benchmark(f, status="unknown", name="benchmark", logic=""):
    """ Convert a Python assertion to a SMT2 staement. This is basically useless"""
    v = (Ast * 0)()
    return z3.Z3_benchmark_to_smtlib_string(f.ctx_ref(), name, logic, status, "", 0, v, f.as_ast())
class NetworkModel:
    """ A container for state, the old way was far too messy, messiness bad """
    def __init__ (self, nodes, addresses):
        """ Initialize things for the model"""
        self.__setOptions ()
        # Networks have nodes, nodes are quite important
        self.node, self.node_list = z3.EnumSort('Node', nodes)
        self.nodes = dict(zip(nodes, self.node_list))
        
        # Also addresses for these nodes
        self.address, self.address_list = z3.EnumSort('Address', addresses)
        self.addresses = dict(zip(addresses, self.address_list))

        # Networks have packets
        packet = z3.Datatype('Packet')
        packet.declare('packet', ('src', self.address), ('dest', self.address), ('origin', self.node))
        self.packet = packet.create()

        # Some functions to keep everything running
        # hostHasAddr: self.node -> self.address -> boolean
        self.hostHasAddr = z3.Function('hostHasAddr', self.node, \
                                            self.address, z3.BoolSort ())
        # addrToHost: self.address -> self.node
        self.addrToHost = z3.Function('addrToHost', self.address, self.node)
        # send := src -> dst -> self.packet -> bool
        self.send = z3.Function('send', self.node, self.node, self.packet, z3.BoolSort ())
        # recv := src -> dst -> self.packet ->bool
        self.recv = z3.Function('recv', self.node, self.node, self.packet, z3.BoolSort ())
        # Create a solver
        self.solver = z3.Solver()
        # Install some basic conditions for the network.
        self.__baseCondition()

    def __setOptions (self):
        """ Set some z3 solver parameters """
        # Produce proofs for model
        z3.set_param('proof', True)
        # Produce core when unsat. I turned this off since this happened to be super slow for some reason.
        #z3.set_param('unsat-core', True)
        # Produce a trace for what z3 does.
        #z3.set_param('trace', True)
        # MBQI: Model based quantifier instantiation is on.
        z3.set_param('smt.mbqi', True)
        # Timeout for MBQI, setting this to a larger number might be useful
        z3.set_param('smt.mbqi.max_iterations', 10000)
        z3.set_param('model.compact', True)
        #z3.set_param('model.partial', True)
        # Simplify nested quantifiers.
        z3.set_param('smt.pull_nested_quantifiers', True)

    def __baseCondition (self):
        """ Set up base conditions for the network"""

        # A few temporary nodes
        eh1 = z3.Const('_base_eh1', self.node)
        eh2 = z3.Const('_base_eh2', self.node)
        eh3 = z3.Const('_base_eh3', self.node)
        eh4 = z3.Const('_base_eh4', self.node)
        # An self.address
        ad1 = z3.Const('_base_ad1', self.address)
        # And a self.packet
        p = z3.Const('__base_packet', self.packet)
        # A host has address iff address belongs to host
        # \forall e_1 \in Node,\ a_1\in Address: hostHasAddr(e_1, a_1) \iff addrToHost(a_1) = e_1
        self.solver.add(z3.ForAll([eh1, ad1], self.hostHasAddr(eh1, ad1) == (self.addrToHost(ad1) == eh1)))

        # All sent packets are received
        # \forall e_1, e_2\in Node , p\in Packet: recv(e_1, e_2, p) \iff send(e_1, e_2, p)
        self.solver.add (z3.ForAll([eh1, eh2, p], self.recv(eh1, eh2, p) ==  self.send(eh1, eh2, p)))
        
        # All received self.packets were once sent (don't invent self.packets).
        # \forall e_1, e_2, p: recv (e_1, e_2, p) \Rightarrow \exists e_3 send(addrToHost(p), e_3, p)
        self.solver.add(z3.ForAll([eh1, eh2, p], z3.Implies(self.recv(eh1, eh2, p),
                                         z3.Exists([eh3], self.send(self.addrToHost(self.packet.src(p)), eh3, p)))))

        # Turn off loopback, loopback makes me sad
        # \forall e_1, e_2, p send(e_1, e_2, p) \Rightarrow e_1 \neq e_2
        # \forall e_1, e_2, p recv(e_1, e_2, p) \Rightarrow e_1 \neq e_2
        self.solver.add(z3.ForAll([eh1, eh2, p], z3.Implies(self.send(eh1, eh2, p), eh1 != eh2)))
        self.solver.add(z3.ForAll([eh1, eh2, p], z3.Implies(self.recv(eh1, eh2, p), eh1 != eh2)))
        self.solver.add(z3.ForAll([eh1, eh2, p], z3.Implies(self.recv(eh1, eh2, p), self.packet.src(p) != self.packet.dest(p))))

    def __saneSend (self, node):
        eh = z3.Const('__saneSend_eh_%s'%(node), self.node)
        p = z3.Const('__saneSend_p_%s'%(node), self.packet)
        # Don't send packets meant for node
        # \forall e, p:\ send (f, e, p) \Rightarow \neg hostHasAddr (f, p.dest)
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(node, eh, p),\
                z3.Not(self.hostHasAddr(node, self.packet.dest(p))))))

    def setAddressMappingsExclusive (self, addrmap):
        """Constraints to ensure that a host has only the addresses in the map"""
        tempAddr = z3.Const("__setAdMapExclusive_address", self.address)
        for host, addr in addrmap.iteritems():
            # addrToHost(h) = a_h
            # \forall a \in address, hostHasAddr(h, a) \iff a = a_h
            self.solver.add(self.addrToHost(self.addresses[addr]) == self.nodes[host])
            self.solver.add(z3.ForAll([tempAddr], self.hostHasAddr(self.nodes[host], tempAddr) == (tempAddr == \
                                    self.addresses[addr])))

    def AdjacencyConstraint (self, nodes, adj):
        if not isinstance(nodes, list):
            nodes = [nodes]
        if not isinstance(adj, list):
            adj = [adj]
        for node in nodes:
            eh = z3.Const('__adjacency_node_%s'%(node), self.node)
            p = z3.Const('__adjacency_packet_%s'%(node), self.packet)
            if len(adj) != 0:
                adjacency_constraint = z3.Or(map(lambda n: eh == self.nodes[n], adj))
                # \forall e_1, p recv(e_1, h, p) \Rightarrow \exists e_2 \in Adj: e_1 = e_2
                # \forall e_1, p send(h, e_1, p) \Rightarrow \exists e_2 \in Adj: e_1 = e_2
                self.solver.add(z3.ForAll([eh, p], z3.Implies(self.recv(eh, node, p),\
                                            adjacency_constraint)))
                self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(node, eh, p),\
                                            adjacency_constraint)))
            else:
                self.solver.add(z3.ForAll([eh, p], z3.Not(self.recv(eh, node, p))))
                self.solver.add(z3.ForAll([eh, p], z3.Not(self.send(node, eh, p))))

    def EndHostRules (self, hosts, adj):
        eh = z3.Const('__nodeRules_Node', self.node)
        p = z3.Const('__nodeRules_Packet', self.packet)
        self.AdjacencyConstraint(map(lambda n: self.nodes[n], hosts), adj)
        for h in hosts:
            h = self.nodes[h]
            # \forall e_1, p: send(h, e_1, p) \Rightarrow hostHasAddr (h, p.src)
            # \forall e_1, p: send(h, e_1, p) \Rightarrow p.origin = h
            self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(h, eh, p), self.hostHasAddr(h, self.packet.src(p)))))
            self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(h, eh, p), self.packet.origin(p) == h)))
    
    def RoutingTable (self, node, routing_table):
        """ Routing entries are of the form address -> node"""
        p = z3.Const('__packet__Routing_%s'%(node), self.packet)
        eh = z3.Const('__node__Routing_%s'%(node), self.node)
        table = map(lambda (n1, n2): (self.addresses[n1], self.nodes[n2]), routing_table.items())
        node = self.nodes[node]
        for entry in table:
            # \forall p: send(n, e[1], p) \iff p.dest == e[0]
            self.solver.add(z3.ForAll([eh, p], z3.Implies(z3.And(self.send(node, eh, p),
                                               (self.packet.dest(p) == entry[0])), 
                                               eh == entry[1])))

    def LearningFirewallRules (self, fw, adj, rules):
        fw_str = fw
        fw = self.nodes[fw]
        self.__saneSend(fw)

        # Model holes as a function
        cached = z3.Function ('__fw_cached_rules_%s'%(fw_str), self.address, self.address, z3.BoolSort())
        addr_a = z3.Const ('__fw_addr_cache_a_%s'%(fw_str), self.address)
        addr_b = z3.Const ('__fw_addr_cache_b_%s'%(fw_str), self.address)

        # Normal firewall rules (same as firewall deny rules, maybe we can combine them somehow) 
        p = z3.Const('__firewall_Packet_%s'%(fw_str), self.packet)
        eh = z3.Const('__firewall_node1_%s'%(fw_str), self.node)
        eh2 = z3.Const('__firewall_node2_%s'%(fw_str), self.node)

        # The firewall never invents self.packets
        # \forall e_1, p\ send (f, e_1, p) \Rightarrow \exists e_2 recv(e_2, f, p)
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p), z3.Exists([eh2], self.recv(eh2, fw, p)))))
        self.AdjacencyConstraint(fw, adj)
        
        if len(rules) == 0:
            return
        conditions = []

        # Firewall rules (These are unidirectional)
        for rule in rules:
            (ada, adb) = rule
            (ada, adb) = (self.addresses[ada], self.addresses[adb])
            conditions.append(z3.And(self.packet.src(p) == ada,
                                        self.packet.dest(p) == adb))
            #conditions.append(z3.And(self.packet.src(p) == adb,
            #                            self.packet.dest(p) == ada))

        # Constraints for what holes are punched 
        # \forall a, b cached(a, b) \iff \exists e, p send(f, e, p) \land 
        #                 p.src == a \land p.dest == b \land \neg(ACL(p))
        self.solver.add(z3.ForAll([addr_a, addr_b], cached(addr_a, addr_b) ==\
                            z3.Exists([eh, p],\
                                z3.And(self.recv(eh, fw, p),\
                                z3.And(self.packet.src (p) == addr_a, self.packet.dest(p) == addr_b,\
                                        z3.Not(z3.Or(conditions)))))))

        # Actually enforce firewall rules
        # \forall e_1, p send(f, e_1, p) \Rightarrow cached(p.src, p.dest) \lor cached(p.dest, p.src) 
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p),\
                    z3.Or(cached(self.packet.src(p), self.packet.dest(p)),\
                        cached(self.packet.dest(p), self.packet.src(p))))))

        

    def FirewallDenyRules (self, fw, adj, rules):
        fw = self.nodes[fw]
        self.__saneSend(fw)
        p = z3.Const('__firewall_Packet_%s'%(fw), self.packet)
        eh = z3.Const('__firewall_node1_%s'%(fw), self.node)
        eh2 = z3.Const('__firewall_node_%s'%(fw), self.node)
        # The firewall never invents self.packets
        # \forall e_1, p\ send (f, e_1, p) \Rightarrow \exists e_2 recv(e_2, f, p)
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p), z3.Exists([eh2], self.recv(eh2, fw, p)))))
        self.AdjacencyConstraint(fw, adj)
        
        if len(rules) == 0:
            return
        conditions = []

        # Firewall rules
        for rule in rules:
            (ada, adb) = rule
            (ada, adb) = (self.addresses[ada], self.addresses[adb])
            conditions.append(z3.And(self.packet.src(p) == ada,
                                        self.packet.dest(p) == adb))
            conditions.append(z3.And(self.packet.src(p) == adb,
                                        self.packet.dest(p) == ada))
        # Actually enforce firewall rules
        # Actually enforce firewall rules
        # \forall e_1, p send(f, e_1, p) \Rightarrow cached(p.src, p.dest) \lor cached(p.dest, p.src) \lor \neg(ACL(p)) 
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p),
                    z3.Not(z3.Or(conditions)))))

    def WebProxyRules (self, proxy, adj):
        p = z3.Const('__webproxy_packet1_%s'%(proxy), self.packet)
        p2 = z3.Const('__webproxy_p2_%s'%(proxy), self.packet)
        eh = z3.Const('__webproxy_eh_%s'%(proxy), self.node)
        eh2 = z3.Const('__webproxy_eh2_%s'%(proxy), self.node)
        proxy = self.nodes[proxy]
        self.__saneSend(proxy)
        self.AdjacencyConstraint(proxy, adj)
        # \forall e, p: send(w, e, p) \Rightarrow hostHasAddr(w, p.src)
        # \forall e_1, p_1: send(w, e, p_1) \Rightarrow \exists e_2, p_2: recv(e_2, w, p_2) \land 
        #                   p_2.origin == p_1.origin \land p_2.dest == p_1.dest \land hostHasAddr(p_2.origin, p_2.src)
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(proxy, eh, p), self.hostHasAddr(proxy, self.packet.src(p)))))
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(proxy, eh, p), z3.Exists([p2, eh2], 
                             z3.And(self.recv(eh2, proxy, p2),
                                 z3.And(z3.And(self.packet.origin(p2) == self.packet.origin(p),
                                        self.packet.dest(p2) == self.packet.dest(p),
                                        self.hostHasAddr(self.packet.origin(p2), self.packet.src(p2)))))))))

    def CheckPacketReachability (self, src, dest, tag = None):
        p = z3.Const('__reachability_Packet_%s_%s'%(src, dest), self.packet)
        eh = z3.Const('__reachability_last_Node_%s_%s'%(src, dest), self.node)
        if tag:
            self.solver.assert_and_track(z3.Exists([eh], self.recv(eh, self.nodes[dest], p)), tag)
        else:
            self.solver.add(z3.Exists([eh], self.recv(eh, self.nodes[dest], p)))
        self.solver.add(self.packet.origin(p) == self.nodes[src])
