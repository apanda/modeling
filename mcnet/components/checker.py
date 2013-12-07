import z3
class PropertyChecker (object):
    """Actually check for properties in the network graph etc."""
    def __init__ (self, context, network):
        self.ctx = context
        self.net = network
        self.solver = z3.Solver()
        self.constraints = list ()
        self.primed = False
    
    def CheckIsolationProperty (self, src, dest):
        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        if not self.primed:
            self.CheckNow()
        self.solver.push ()
        p = z3.Const('__reachability_Packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        eh = z3.Const('__reachability_last_Node_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        self.solver.add(z3.Exists([eh], self.ctx.recv(eh, dest.z3Node, p)))
        self.solver.add(self.ctx.packet.origin(p) == src.z3Node)
        self.result = self.solver.check() 
        if self.result == z3.sat:
            self.model = self.solver.model ()
        self.solver.pop()
        return self.result

    def CheckImpliedIsolation (self, srcn, destn, src, dest):
        assert(srcn in self.net.elements)
        assert(destn in self.net.elements)
        if not self.primed:
            self.CheckNow()
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
        self.result = self.solver.check()
        if self.result == z3.sat:
            self.model = self.solver.model ()
        self.solver.pop()
        return self.result
    
    def CheckNow (self):
        self.ctx._addConstraints(self.solver)
        self.net._addConstraints(self.solver)
        for el in self.net.elements:
            el._addConstraints(self.solver)
        self.primed = True
