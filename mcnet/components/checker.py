import z3
class PropertyChecker (object):
    """Actually check for properties in the network graph etc."""
    def __init__ (self, context, network):
        self.ctx = context
        self.net = network
        self.solver = z3.Solver()
        self.constraints = list ()
        self.primed = False

    # Just use the NULL predicate
    def CheckIsolationProperty (self, src, dest):
        class IsolationResult (object):
            def __init__ (self, result, violating_packet, last_hop, model = None):
                self.result = result
                self.violating_packet = violating_packet
                self.last_hop = last_hop
                self.model = model
            
        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        if not self.primed:
            self.AddConstraints()
        self.solver.push ()
        p = z3.Const('__reachability_Packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        eh = z3.Const('__reachability_last_Node_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        self.solver.add(z3.Exists([eh], self.ctx.recv(eh, dest.z3Node, p)))
        self.solver.add(self.ctx.packet.origin(p) == src.z3Node)
        result = self.solver.check()
        model = None
        if result == z3.sat:
            model = self.solver.model ()
        self.solver.pop()
        return IsolationResult(result, p, eh, model)

    # Convert to a predicate used by CheckImpliedIsolation
    def CheckImpliedIsolation (self, srcn, destn, src, dest):
        class ImpliedIsolationResult (object):
            def __init__ (self, result, violating_packet, last_hop, implied_packet, implied_last_hop, model = None):
                self.result = result
                self.violating_packet = violating_packet
                self.last_hop = last_hop
                self.implied_packet = implied_packet
                self.implied_last_hop = implied_last_hop
                self.model = model

        assert(srcn in self.net.elements)
        assert(destn in self.net.elements)
        if not self.primed:
            self.AddConstraints()
        self.solver.push()
        pn = z3.Const('__implied_reachability_neg_Packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        ehn = z3.Const('__implied_reachability_neg_last_Node_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        p = z3.Const('__implied_reachability_Packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        eh = z3.Const('__implied_reachability_last_Node_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        self.solver.add(z3.And(z3.Not(z3.Exists([pn, ehn], \
                               z3.And(self.ctx.recv(ehn, destn.z3Node, pn), \
                                       self.ctx.packet.origin(pn) == srcn.z3Node))),
                               z3.And(z3.Exists([eh], \
                                       self.ctx.recv(eh, dest.z3Node, p)), \
                                       self.ctx.packet.origin(p) == src.z3Node)))
        result = self.solver.check()
        model = None
        if result == z3.sat:
            model = self.solver.model ()
        self.solver.pop()
        return ImpliedIsolationResult(result, p, eh, pn, ehn, model)

    def CheckIsolatedIf (self, predicate, src, dest):
        """Check for isolation given a predicate on the packet"""
        class IsolationResult (object):
            def __init__ (self, result, violating_packet, last_hop, model = None):
                self.result = result
                self.violating_packet = violating_packet
                self.last_hop = last_hop
                self.model = model

        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        if not self.primed:
            self.AddConstraints()
        self.solver.push()
        p = z3.Const('__reachability_Packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        eh = z3.Const('__reachability_last_Node_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        self.solver.add(z3.Exists([eh], z3.And(predicate(p), \
                                self.ctx.recv(eh, dest.z3Node, p))))
        self.solver.add(self.ctx.packet.origin(p) == src.z3Node)
        result = self.solver.check()
        model = None
        if result == z3.sat:
            model = self.solver.model ()
        self.solver.pop()
        return IsolationResult (result, p, eh, model)


    def AddConstraints (self):
        self.ctx._addConstraints(self.solver)
        self.net._addConstraints(self.solver)
        for el in self.net.elements:
            el._addConstraints(self.solver)
        self.primed = True
