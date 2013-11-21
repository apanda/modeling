""" Network model definitions"""
import z3
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
        # Events we care about. Currently we just care about sending and receiving (events at active elements
        # are handled differently, c.f. learning firewall)
        self.events, [self.send_event, self.recv_event] = z3.EnumSort('Events', ['__ev_send', '__ev_recv'])

        # Networks have packets
        packet = z3.Datatype('Packet')
        packet.declare('packet', \
                       ('src', self.address), \
                       ('sport', z3.IntSort()), \
                       ('dest', self.address), \
                       ('dport', z3.IntSort()), \
                       ('origin', self.node), \
                       ('id', z3.IntSort()), \
                       ('seq', z3.IntSort()))
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
        # Time at which packet is processed
        # etime := node -> packet -> event -> int 
        self.etime = z3.Function('etime', self.node, self.packet, self.events, z3.IntSort ())
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
        #z3.set_param('smt.mbqi.max_iterations', 10000)
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
        p2 = z3.Const('__base_packet_2', self.packet)

        # self.solver.add(z3.ForAll([p], z3.And(self.packet.sport(p) > 0, \
        #                    self.packet.dport(p) > 0, \
        #                    self.packet.sport(p) < 65535, \
        #                    self.packet.dport(p) < 65535)))
        self.solver.add(z3.ForAll([eh1, eh2, p], z3.Implies(self.send(eh1, eh2, p),
                                                  z3.And(self.packet.sport(p) > 0, \
                                                  self.packet.dport(p) > 0, \
                                                  self.packet.sport(p) < 65535, \
                                                  self.packet.dport(p) < 65535))))
        # A host has address iff address belongs to host
        # \forall e_1 \in Node,\ a_1\in Address: hostHasAddr(e_1, a_1) \iff addrToHost(a_1) = e_1
        #self.solver.add(z3.ForAll([eh1, ad1], self.hostHasAddr(eh1, ad1) == (self.addrToHost(ad1) == eh1)))

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

        # Rules for time
        # Received packets have time, don't receive before sent
        # \forall e_1, e_2, p: recv(e_1, e_2, p) \Rightarrow etime(e_2, p, R) >
        #                                 0 \land etime(e_2, p, R) > etime(e_1, p, S)
        self.solver.add(z3.ForAll([eh1, eh2, p], z3.Implies(self.recv(eh1, eh2, p), z3.And(\
                            self.etime(eh2, p, self.recv_event) > 0, \
                            self.etime(eh2, p, self.recv_event) > self.etime(eh1, p, self.send_event)))))
        # All sent packets have an event time
        # \forall e_1, e_2, p: send(e_1, e_2, p) \Rightarrow etime(e_1, p, S) >
        #                             0 \land etime(e_2, p, R) > etime(e_1, p, S)
        self.solver.add(z3.ForAll([eh1, eh2, p], z3.Implies(self.send(eh1, eh2, p), 
                            z3.And(self.etime(eh1, p, self.send_event) > 0, \
                            self.etime(eh2, p, self.recv_event) > self.etime(eh1, p, self.send_event)))))
        # Unreceved packets always have recv etime of 0
        # \forall e_1, p: (\notexists e_2: recv(e_2, e_1, p)) \Rightarrow etime(e_1, p, R) = 0
        self.solver.add(z3.ForAll([eh1, p], z3.Implies(z3.Not(z3.Exists([eh2], self.recv(eh2, eh1, p))), \
                                    self.etime(eh1, p, self.recv_event) == 0)))
        # Unreceved packets always have send etime of 0
        # \forall e_1, p: (\notexists e_2: send(e_1, e_2, p)) \Rightarrow etime(e_1, p, S) = 0
        self.solver.add(z3.ForAll([eh1, p], z3.Implies(z3.Not(z3.Exists([eh2], self.send(eh1, eh2, p))), \
                                    self.etime(eh1, p, self.send_event) == 0)))

    def __saneSend (self, node):
        eh = z3.Const('__saneSend_eh_%s'%(node), self.node)
        p = z3.Const('__saneSend_p_%s'%(node), self.packet)
        # Don't send packets meant for node
        # \forall e, p:\ send (f, e, p) \Rightarow \neg hostHasAddr (f, p.dest)
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(node, eh, p), \
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
    def setLoadBalancedAddressMapping (self, lbaddr, addrmap):
        """Constraints to ensure that a host has only the addresses in the map"""
        tempAddr = z3.Const("__setAdMapExclusive_address", self.address)
        for host, addr in addrmap.iteritems():
            # addrToHost(h) = a_h
            # \forall a \in address, hostHasAddr(h, a) \iff a = a_h
            self.solver.add(self.addrToHost(self.addresses[addr]) == self.nodes[host])
            self.solver.add(z3.ForAll([tempAddr], self.hostHasAddr(self.nodes[host], tempAddr) == \
                                z3.Or(tempAddr == self.addresses[addr], \
                                      tempAddr == self.addresses[lbaddr])))
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
                self.solver.add(z3.ForAll([eh, p], z3.Implies(self.recv(eh, node, p), \
                                            adjacency_constraint)))
                self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(node, eh, p), \
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
            self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(h, eh, p), \
                self.hostHasAddr(h, self.packet.src(p)))))
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
        cached = z3.Function ('__fw_cached_rules_%s'%(fw_str), self.address, z3.IntSort(), \
                                            self.address, z3.IntSort(), z3.BoolSort())
        ctime = z3.Function ('__fw_cached_time_%s'%(fw_str), self.address, z3.IntSort(), \
                                    self.address, z3.IntSort(), z3.IntSort())
        addr_a = z3.Const ('__fw_addr_cache_a_%s'%(fw_str), self.address)
        addr_b = z3.Const ('__fw_addr_cache_b_%s'%(fw_str), self.address)

        # Normal firewall rules (same as firewall deny rules, maybe we can combine them somehow) 
        p = z3.Const('__firewall_Packet_%s'%(fw_str), self.packet)
        eh = z3.Const('__firewall_node1_%s'%(fw_str), self.node)
        eh2 = z3.Const('__firewall_node2_%s'%(fw_str), self.node)

        # The firewall never invents self.packets
        # \forall e_1, p\ send (f, e_1, p) \Rightarrow \exists e_2 recv(e_2, f, p)
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p), \
                z3.Exists([eh2], \
                 z3.And(self.recv(eh2, fw, p), \
                    self.etime(fw, p, self.recv_event) < \
                        self.etime(fw, p, self.send_event))))))
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
        port1 = z3.Const('__fw_port_1_%s'%(fw_str), z3.IntSort())
        port2 = z3.Const('__fw_port_2_%s'%(fw_str), z3.IntSort())
        self.solver.add(z3.ForAll([addr_a, port1, addr_b, port2, eh], z3.Implies(\
                        z3.Not(cached(addr_a, port1, addr_b, port2)), \
                        ctime (addr_a, port1, addr_b, port2) == 0)))
        # Constraints for what holes are punched 
        # \forall a, b cached(a, b) \iff \exists e, p send(f, e, p) \land 
        #                 p.src == a \land p.dest == b \land ctime(a, b) = etime(fw, p, R) \land
        #                   neg(ACL(p))
        self.solver.add(z3.ForAll([addr_a, addr_b, port1, port2], cached(addr_a, port1, addr_b, port2) ==\
                            z3.Exists([eh, p], \
                                z3.And(self.recv(eh, fw, p), \
                                z3.And(self.packet.src (p) == addr_a, self.packet.dest(p) == addr_b, \
                                       self.packet.sport (p) == port1, self.packet.dport(p) == port2, \
                                        ctime (addr_a, port1, addr_b, port2) ==\
                                                self.etime(fw, p, self.recv_event), \
                                        z3.Not(z3.Or(conditions)))))))

        # Actually enforce firewall rules
        # \forall e_1, p send(f, e_1, p) \Rightarrow (cached(p.src, p.dest)
        #                       \land ctime(p.src, p.dest) <= etime(fw, p, R))
        #                       \lor (cached(p.dest, p.src) \land ctime(p.dest, p.src) <= etime(fw. p, R))
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p), \
                    z3.Or(z3.And(cached(self.packet.src(p), self.packet.sport(p), \
                                            self.packet.dest(p), self.packet.dport(p)), \
                                        ctime(self.packet.src(p), self.packet.sport(p), \
                                              self.packet.dest(p), self.packet.dport(p)) <=\
                                                        self.etime(fw, p, self.recv_event)), \
                                 z3.And(cached(self.packet.dest(p), self.packet.dport(p), \
                                            self.packet.src(p), self.packet.sport(p)), \
                                        ctime(self.packet.dest(p), self.packet.dport(p), \
                                              self.packet.src(p), self.packet.sport(p)) <=\
                                                        self.etime(fw, p, self.recv_event))))))

    def FirewallDenyRules (self, fw, adj, rules):
        fw = self.nodes[fw]
        self.__saneSend(fw)
        p = z3.Const('__firewall_Packet_%s'%(fw), self.packet)
        eh = z3.Const('__firewall_node1_%s'%(fw), self.node)
        eh2 = z3.Const('__firewall_node_%s'%(fw), self.node)
        # The firewall never invents self.packets
        # \forall e_1, p\ send (f, e_1, p) \Rightarrow \exists e_2 recv(e_2, f, p)
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p), \
                                 z3.And(z3.Exists([eh2], self.recv(eh2, fw, p)), \
                                        self.etime(fw, p, self.send_event) >\
                                        self.etime(fw, p, self.recv_event)))))
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
        p3 = z3.Const('__webproxy_p3_%s'%(proxy), self.packet)
        p4 = z3.Const('__webproxy_p4_%s'%(proxy), self.packet)
        eh = z3.Const('__webproxy_eh_%s'%(proxy), self.node)
        eh2 = z3.Const('__webproxy_eh2_%s'%(proxy), self.node)
        eh3 = z3.Const('__webproxy_eh3_%s'%(proxy), self.node)

        a1 = z3.Const('__webproxy_cache_addr_%s'%(proxy), self.address)
        i1 = z3.Const('__webproxy_cache_port_%s'%(proxy), z3.IntSort())
        i2 = z3.Const('__webproxy_cache_id_%s'%(proxy), z3.IntSort())
        cached = z3.Function('__webproxy_cached_%s'%(proxy), self.address, z3.IntSort(), z3.IntSort(), \
                                    z3.BoolSort())
        ctime = z3.Function('__webproxy_ctime_%s'%(proxy), self.address, z3.IntSort(), z3.IntSort(), \
                                    z3.IntSort())
        cresp = z3.Function('__webproxy_cresp_%s'%(proxy), self.address, z3.IntSort(), z3.IntSort(), \
                                    z3.IntSort())
        corigin = z3.Function('__webproxy_corigin_%s'%(proxy), self.address, z3.IntSort(), \
                                    z3.IntSort(), self.node)

        proxy = self.nodes[proxy]
        self.__saneSend(proxy)
        
        # Model cache as a function
        # If not cached, cache time is 0
        self.solver.add(z3.ForAll([a1, i1, i2], z3.Not(cached(a1, i1, i2)) == (ctime(a1, i1, i2) == 0)))
        self.solver.add(z3.ForAll([a1, i1, i2], z3.Not(cached(a1, i1, i2)) == (cresp(a1, i1, i2) == 0)))

        cache_condition = z3.ForAll([a1, i1, i2], \
                            z3.Implies(cached(a1, i1, i2), \
                             z3.Exists([p, eh], \
                              z3.And(\
                                self.recv(eh, proxy, p), \
                                self.packet.src(p) == a1, \
                                self.packet.id(p) == cresp(a1, i1, i2), \
                                corigin(a1, i1, i2) == self.packet.origin(p), \
                                self.packet.sport(p) == i1, \
                                self.hostHasAddr(proxy, self.packet.dest(p)), \
                                self.etime (proxy, p, self.recv_event) == ctime(a1, i1, i2), \
                                z3.Exists([p2], \
                                z3.And(\
                                    self.etime(proxy, p2, self.send_event) > 0, \
                                    self.etime(proxy, p2, self.send_event) <= ctime(a1, i1, i2), \
                                    self.etime(self.addrToHost(a1), p, self.send_event) > 
                                        self.etime(self.addrToHost(a1), p2, self.recv_event), \
                                    self.packet.dest(p2) == a1, \
                                    self.packet.id(p2) == i2, \
                                    self.packet.dport(p2) == i1, \
                                    self.hostHasAddr(proxy, self.packet.src(p2)), \
                                    self.packet.origin(p2) != proxy
                                ))))))
                              
        self.solver.add(cache_condition)


        self.AdjacencyConstraint(proxy, adj)
        # \forall e, p: send(w, e, p) \Rightarrow hostHasAddr(w, p.src)
        # \forall e_1, p_1: send(w, e, p_1) \Rightarrow \exists e_2, p_2: recv(e_2, w, p_2) \land 
        #                   p_2.origin == p_1.origin \land p_2.dest == p_1.dest \land hostHasAddr(p_2.origin, p_2.src)
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(proxy, eh, p), \
                            self.hostHasAddr(proxy, self.packet.src(p)))))

        cached_packet = z3.And(cached(self.packet.dest(p2), self.packet.dport(p2), self.packet.id(p2)), \
                                self.etime(proxy, p2, self.recv_event) >= \
                                    ctime(self.packet.dest(p2), self.packet.dport(p2), self.packet.id(p2)), \
                                self.packet.id(p) == cresp(self.packet.dest(p2), self.packet.dport(p2), \
                                                                                    self.packet.id(p2)), \
                                self.packet.dest(p) == self.packet.src(p2), \
                                self.packet.origin(p) == corigin(self.packet.dest(p2), self.packet.dport(p2), \
                                                                self.packet.id(p2)), \
                                self.packet.sport(p) == self.packet.dport(p2))

        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(proxy, eh, p), z3.Exists([p2, eh2], 
                             z3.And(self.recv(eh2, proxy, p2),
                              z3.Or(\
                               z3.And(self.packet.origin(p2) == self.packet.origin(p),
                                      self.packet.dest(p2) == self.packet.dest(p), \
                                      self.packet.id(p2) == self.packet.id(p), \
                                      self.packet.seq(p2) == self.packet.seq(p), \
                                      self.hostHasAddr(self.packet.origin(p2), self.packet.src(p2)), \
                                      self.packet.dport(p2) == self.packet.dport(p), \
                                      self.etime(proxy, p, self.send_event) > \
                                        self.etime(proxy, p2, self.recv_event)), \
                               cached_packet))))))

    
    def LoadBalancer (self, balancer, adj, outaddr, outports):
        lbalancer = self.nodes[balancer]
        # sane send is good
        self.__saneSend(lbalancer)
        # Load balancers have adjacency constraints
        self.AdjacencyConstraint (lbalancer, adj)
        flow_hash = z3.Function('__lb_flow_hash_%s'%(balancer), \
                                        self.address, \
                                        z3.IntSort(), \
                                        self.address, \
                                        z3.IntSort(), \
                                        z3.IntSort())
        p1 = z3.Const('__lb_packet1_%s'%(balancer), self.packet)
        p2 = z3.Const('__lb_packet2_%s'%(balancer), self.packet)
        eh1 = z3.Const('__lb_node_eh1_%s'%(balancer), self.node)
        eh2 = z3.Const('__lb_node_eh2_%s'%(balancer), self.node)

        saddr = z3.Const('__lb_node_sa1_%s'%(balancer), self.address)
        daddr = z3.Const('__lb_node_da1_%s'%(balancer), self.address)
        sport = z3.Const('__lb_node_sp1_%s'%(balancer), z3.IntSort())
        dport = z3.Const('__lb_node_dp1_%s'%(balancer), z3.IntSort())
        
        # Limit the range of the flow hashing function
        # \forall a_1, x, a_2, y: flow_hash(a_1, x, a_2, y) \geq 0 
        self.solver.add(z3.ForAll([saddr, sport, daddr, dport], \
                flow_hash (saddr, \
                           sport, \
                           daddr, \
                           dport) >= 0))
        # \forall a_1, x, a_2, y: flow_hash(a_1, x, a_2, y) \leq len(outports) 
        self.solver.add(z3.ForAll([saddr, sport, daddr, dport], \
                flow_hash (saddr, \
                           sport, \
                           daddr, \
                           dport) < len(outports)))
        # TODO: Maybe think about doing this in bit vectors
        # \forall a_1, x, a_2, y: flow_hash(a_1, x, a_2, y) = (x + y) % len(outports) 
        self.solver.add(z3.ForAll([saddr, sport, daddr, dport], \
                flow_hash (saddr, \
                           sport, \
                           daddr, \
                           dport) == (dport + sport) % len(outports)))

        # Load balancers don't create any packets, ever
        self.solver.add(z3.ForAll([eh1, p1], z3.Implies(self.send(lbalancer, eh1, p1), \
                                 z3.And(z3.Exists([eh2], self.recv(eh2, lbalancer, p1)), \
                                        self.etime(lbalancer, p1, self.send_event) >\
                                        self.etime(lbalancer, p1, self.recv_event)))))
        outaddr = self.addresses[outaddr]
        outputs = map(lambda p: self.nodes[p], outports)
        input_clause = map(lambda n: eh1 == n, outputs)
        # Send out packet based on flow hashing
        self.solver.add(z3.ForAll([eh1, p1], \
                z3.Implies(\
                 z3.And(self.send(lbalancer, eh1, p1), \
                        self.packet.dest(p1) == outaddr), \
                 z3.Or (input_clause))))
        for idx, node in zip(range(len(outputs)), outputs):
            self.solver.add(z3.ForAll([p1], \
                    z3.Implies(self.send(lbalancer, node, p1),
                        z3.Or(z3.Not(self.packet.dest(p1) == outaddr),\
                        flow_hash(self.packet.src(p1), self.packet.sport(p1), \
                                self.packet.dest(p1), self.packet.dport(p1)) == idx))))
    def CheckPacketReachability (self, src, dest, tag = None):
        p = z3.Const('__reachability_Packet_%s_%s'%(src, dest), self.packet)
        eh = z3.Const('__reachability_last_Node_%s_%s'%(src, dest), self.node)
        if tag:
            self.solver.assert_and_track(z3.Exists([eh], self.recv(eh, self.nodes[dest], p)), tag)
        else:
            self.solver.add(z3.Exists([eh], self.recv(eh, self.nodes[dest], p)))
        self.solver.add(self.packet.origin(p) == self.nodes[src])
