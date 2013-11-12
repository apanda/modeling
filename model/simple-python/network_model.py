import z3
def toSMT2Benchmark(f, status="unknown", name="benchmark", logic=""):
    """ Convert a Python assertion to a SMT2 staement. This is basically useless"""
    v = (Ast * 0)()
    return z3.Z3_benchmark_to_smtlib_string(f.ctx_ref(), name, logic, status, "", 0, v, f.as_ast())
class NetworkModel:
    """ A container for state, the old way was far too messy, messiness bad """
    def __init__ (self, endhosts, addresses):
        """ Initialize things for the model"""
        self.__setOptions ()
        # Networks have endhosts, endhosts are quite important
        self.endhost, self.endhost_list = z3.EnumSort('Endhost', endhosts)
        self.endhosts = dict(zip(endhosts, self.endhost_list))
        
        # Also addresses for these endhosts
        self.address, self.address_list = z3.EnumSort('Address', addresses)
        self.addresses = dict(zip(addresses, self.address_list))

        # Networks have packets
        packet = z3.Datatype('Packet')
        packet.declare('packet', ('src', self.address), ('dest', self.address), ('origin', self.endhost))
        self.packet = packet.create()

        # Some functions to keep everything running
        # hostHasAddr: self.endhost -> self.address -> boolean
        self.hostHasAddr = z3.Function('hostHasAddr', self.endhost, \
                                            self.address, z3.BoolSort ())
        # addrToHost: self.address -> self.endhost
        self.addrToHost = z3.Function('addrToHost', self.address, self.endhost)
        # send := src -> dst -> self.packet -> bool
        self.send = z3.Function('send', self.endhost, self.endhost, self.packet, z3.BoolSort ())
        # recv := src -> dst -> self.packet ->bool
        self.recv = z3.Function('recv', self.endhost, self.endhost, self.packet, z3.BoolSort ())
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

        # A few temporary endhosts
        eh1 = z3.Const('_base_eh1', self.endhost)
        eh2 = z3.Const('_base_eh2', self.endhost)
        eh3 = z3.Const('_base_eh3', self.endhost)
        eh4 = z3.Const('_base_eh4', self.endhost)
        # An self.address
        ad1 = z3.Const('_base_ad1', self.address)
        # And a self.packet
        p = z3.Const('__base_packet', self.packet)
        # A host has address iff address belongs to host
        self.solver.add(z3.ForAll([eh1, ad1], self.hostHasAddr(eh1, ad1) == (self.addrToHost(ad1) == eh1)))

        # All sent packets are received
        self.solver.add (z3.ForAll([eh1, eh2, p], self.recv(eh1, eh2, p) ==  self.send(eh1, eh2, p)))
        
        # All received self.packets were once sent (don't invent self.packets).
        self.solver.add(z3.ForAll([eh1, eh2, p], z3.Implies(self.recv(eh1, eh2, p),
                                         z3.Exists([eh3], self.send(self.addrToHost(self.packet.src(p)), eh3, p)))))

        # Turn off loopback, loopback makes me sad
        self.solver.add(z3.ForAll([eh1, eh2, p], z3.Implies(self.send(eh1, eh2, p), eh1 != eh2)))
        self.solver.add(z3.ForAll([eh1, eh2, p], z3.Implies(self.recv(eh1, eh2, p), eh1 != eh2)))
        #self.solver.add(z3.ForAll([eh1, eh2, p], z3.Implies(self.recv(eh1, eh2, p), self.packet.src(p) != self.packet.dest(p))))

    def setAddressMappingsExclusive (self, addrmap):
        """Constraints to ensure that a host has only the addresses in the map"""
        tempAddr = z3.Const("__setAdMapExclusive_address", self.address)
        for host, addr in addrmap.iteritems():
            self.solver.add(self.addrToHost(self.addresses[addr]) == self.endhosts[host])
            self.solver.add(z3.ForAll([tempAddr], self.hostHasAddr(self.endhosts[host], tempAddr) == (tempAddr == \
                                    self.addresses[addr])))

    def EndHostRules (self, hosts, adj):
        eh = z3.Const('__endhostRules_Endhost', self.endhost)
        p = z3.Const('__endhostRules_Packet', self.packet)
        adjacency_constraint = z3.Or(map(lambda n: eh == self.endhosts[n], adj))
        for h in hosts:
            h = self.endhosts[h]
            self.solver.add(z3.ForAll([eh, p], z3.Implies(self.recv(eh, h, p), self.hostHasAddr(h, self.packet.dest(p)))))
            self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(h, eh, p), self.hostHasAddr(h, self.packet.src(p)))))
            self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(h, eh, p), self.packet.origin(p) == h)))
            self.solver.add(z3.ForAll([eh, p], z3.Implies(self.recv(eh, h, p),\
                                        adjacency_constraint)))
            self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(h, eh, p),\
                                        adjacency_constraint)))

    def LearningFirewallRules (self, fw, adj, rules):
        fw_str = fw
        fw = self.endhosts[fw]
        # Model holes as a function
        cached = z3.Function ('__fw_cached_rules_%s'%(fw_str), self.address, self.address, z3.BoolSort())
        p = z3.Const ('__fw_Packet_cache_%s'%(fw_str), self.packet)
        addr_a = z3.Const ('__fw_addr_cache_a_%s'%(fw_str), self.address)
        addr_b = z3.Const ('__fw_addr_cache_b_%s'%(fw_str), self.address)
        eh = z3.Const ('__eh_cache_%s'%(fw_str), self.endhost)

        # Normal firewall rules (same as firewall deny rules, maybe we can combine them somehow) 
        p = z3.Const('__firewall_Packet_%s'%(fw_str), self.packet)
        eh = z3.Const('__firewall_endhost1_%s'%(fw_str), self.endhost)
        eh2 = z3.Const('__firewall_endhost2_%s'%(fw_str), self.endhost)
        # The firewall never invents self.packets
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p), z3.Exists([eh2], self.recv(eh2, fw, p)))))

        adjacency_constraint = z3.Or(map(lambda n: eh == self.endhosts[n], adj))
        # This is just about connectivity
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.recv(eh, fw, p),\
                                adjacency_constraint)))
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p),\
                                adjacency_constraint)))

        if len(rules) == 0:
            return
        conditions = []

        # Firewall rules
        for rule in rules:
            (ada, adb) = rule
            (ada, adb) = (self.addresses[ada], self.addresses[adb])
            conditions.append(z3.And(self.packet.src(p) == ada,
                                        self.packet.dest(p) == adb))
            #conditions.append(z3.And(self.packet.src(p) == adb,
            #                            self.packet.dest(p) == ada))

        # Constraints for what holes are punched (This is a bidirectional)
        self.solver.add(z3.ForAll([addr_a, addr_b], cached(addr_a, addr_b) ==\
                            z3.Exists([eh, p],\
                                z3.And(self.send(fw, eh, p),\
                                z3.Or(z3.And(self.packet.src (p) == addr_a, self.packet.dest(p) == addr_b,\
                                        z3.Not(z3.Or(conditions))),\
                                     z3.And(self.packet.dest (p) == addr_a, self.packet.src(p) == addr_b,\
                                     z3.Not(z3.Or(conditions))))))))

        # Actually enforce firewall rules
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p),
                    z3.Or(cached(self.packet.src(p), self.packet.dest(p)),
                        z3.Not(z3.Or(conditions))))))

        

    def FirewallDenyRules (self, fw, adj, rules):
        p = z3.Const('__firewall_Packet_%s'%(fw), self.packet)
        eh = z3.Const('__firewall_endhost1_%s'%(fw), self.endhost)
        eh2 = z3.Const('__firewall_endhost_%s'%(fw), self.endhost)
        fw = self.endhosts[fw]
        # The firewall never invents self.packets
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p), z3.Exists([eh2], self.recv(eh2, fw, p)))))
        adjacency_constraint = z3.Or(map(lambda n: eh == self.endhosts[n], adj))
        # This is just about connectivity
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.recv(eh, fw, p),\
                                adjacency_constraint)))
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p),\
                                adjacency_constraint)))

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
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(fw, eh, p),
                    z3.Not(z3.Or(conditions)))))

    def WebProxyRules (self, proxy, adj):
        p = z3.Const('__webproxy_packet1_%s'%(proxy), self.packet)
        p2 = z3.Const('__webproxy_p2_%s'%(proxy), self.packet)
        eh = z3.Const('__webproxy_eh_%s'%(proxy), self.endhost)
        eh2 = z3.Const('__webproxy_eh2_%s'%(proxy), self.endhost)
        proxy = self.endhosts[proxy]
        if len(adj) != 0:
            adjacency_constraint = z3.Or(map(lambda n: eh == self.endhosts[n], adj))
            # This is just about connectivity
            self.solver.add(z3.ForAll([eh, p], z3.Implies(self.recv(eh, proxy, p),\
                                    adjacency_constraint)))
            self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(proxy, eh, p),\
                                    adjacency_constraint)))
        else:
            self.solver.add(z3.ForAll([eh, p], z3.Not(self.recv(eh, proxy, p))))
            self.solver.add(z3.ForAll([eh, p], z3.Not(self.send(proxy, eh, p))))
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(proxy, eh, p), self.hostHasAddr(proxy, self.packet.src(p)))))
        self.solver.add(z3.ForAll([eh, p], z3.Implies(self.send(proxy, eh, p), z3.Exists([p2, eh2], 
                             z3.And(self.recv(eh2, proxy, p2),
                                 z3.And(z3.And(self.packet.origin(p2) == self.packet.origin(p),
                                        self.packet.dest(p2) == self.packet.dest(p),
                                        self.hostHasAddr(self.packet.origin(p2), self.packet.src(p2)))))))))
    def CheckPacketReachability (self, src, dest, tag = None):
        p = z3.Const('__reachability_Packet_%s_%s'%(src, dest), self.packet)
        eh = z3.Const('__reachability_last_Endhost_%s_%s'%(src, dest), self.endhost)
        if tag:
            self.solver.assert_and_track(z3.Exists([eh], self.recv(eh, self.endhosts[dest], p)), tag)
        else:
            self.solver.add(z3.Exists([eh], self.recv(eh, self.endhosts[dest], p)))
        self.solver.add(self.packet.origin(p) == self.endhosts[src])
