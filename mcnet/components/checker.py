import z3
class Constraints (object):
    pass
class PropertyChecker (object):
    """Actually check for properties in the network graph etc."""
    
    # Functions across constraints
    def __init__ (self, context, network):
        """Initialize a property checker for this specific class"""
        self.ctx = context
        self.net = network
        self.solver = z3.Solver()
        self.constraints = list ()

    def ClearState (self):
        """Clear everything in the solver"""
        self.solver.reset()
        self.constraints = list()

    def CheckConstraints (self, constraints):
        """Check a given set of constraints. This is equivalent to checking a certain condition.
        Returns a result and a model (which might be None if the constraints cannot be satisfied)"""
        self.solver.push ()
        self.AddConstraints()
        if isinstance(constraints, Constraints):
            constraints = constraints.constraints
        self.solver.add(constraints)
        result = self.solver.check()
        model = None
        if result == z3.sat:
            model = self.solver.model ()
        self.solver.pop()
        return result, model

    def AddExternalConstraints (self, constraints):
        """Add external constraints to the solver."""
        self.solver.push ()
        self.solver.add (constraints)

    def ClearExternalConstraints (self):
        """Remove any external constraints"""
        self.ClearState()

    def AddConstraints (self):
        """Add constraints for the network model to the solver."""
        self.ctx._addConstraints(self.solver)
        self.net._addConstraints(self.solver)
        for el in self.net.elements:
            el._addConstraints(self.solver)

    def PrintTimeline (self, ret):
        """Print a timeline of packets sent and received"""
        print '\n'.join(map(lambda l: str('(%s, %s, %s) -> %s'%(l[0], l[1], l[2], l[3])), \
               sorted(ret.model[ret.model[ret.ctx.etime].else_value().decl()].as_list()[:-1], \
               key=lambda l: l[-1].as_long())))

    def PrintRecv (self, ret):
        """Print set of received packets"""
        print '\n'.join(map(lambda l: str('(%s, %s, %s) -> %s'%(l[0], l[1], l[2], l[3])), \
                    ret.model[ret.model[ret.ctx.recv].else_value().decl()].as_list()[:-1]))
    
    # Specific constraints
    def  IsolationConstraint (self, src, dest):
        """Constraint for Origin Isolation"""
        class IsolationConstraint (Constraints):
            def __init__ (self, constraints, violating_packet, last_hop, ctx):
                self.violating_packet = violating_packet
                self.last_hop = last_hop
                self.ctx = ctx
                self.constraints = constraints

        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        p = z3.Const('__reachability_Packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        eh = z3.Const('__reachability_last_Node_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        constraints = list()
        constraints.append(z3.Exists([eh], self.ctx.recv(eh, dest.z3Node, p)))
        constraints.append(self.ctx.packet.origin(p) == src.z3Node)
        return IsolationConstraint(constraints, p, eh, self.ctx)


    def CheckIsolationProperty (self, src, dest):
        """Check origin isolation"""
        constraints = self.IsolationConstraint (src, dest)
        ret, model = self.CheckConstraints(constraints)
        constraints.result = ret
        constraints.model = model
        return constraints

    def PredicatedIsolationConstraint (self, predicate, src, dest):
        """Origin isolation predicated on some condition being met"""
        class PredicatedIsolationConstraint (Constraints):
            def __init__ (self, constraints, violating_packet, last_hop, ctx):
                self.ctx = ctx
                self.violating_packet = violating_packet
                self.last_hop = last_hop
                self.constraints = constraints
        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        p = z3.Const('__reachability_Packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        eh = z3.Const('__reachability_last_Node_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        constraints = list()
        constraints.append(z3.Exists([eh], z3.And(predicate(p), \
                            self.ctx.recv(eh, dest.z3Node, p))))
        constraints.append(self.ctx.packet.origin(p) == src.z3Node)
        return PredicatedIsolationConstraint(constraints, p, eh, self.ctx)

    def CheckIsolatedIf (self, predicate, src, dest):
        """Check for isolation given a predicate on the packet"""
        constraints = self.PredicatedIsolationConstraint(predicate, src, dest)
        result, model = self.CheckConstraints(constraints)
        constraints.result = result
        constraints.model = model
        return constraints

    def TraversalConstraint (self, src, dest, traverse):
        """Do packets traverse a certain path"""
        class TraversalConstraint (Constraints):
            def __init__ (self, constraintis, bad_packet, ctx):
                self.ctx = ctx
                self.violating_packet = bad_packet
                self.constraints = constraints
        # We want these to be in the path. Checking properties for an unreachable thing are well kind of strange.
        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        assert(traverse in self.net.elements)
        p = z3.Const('traversal_packet_%s_%s_%s'%(src.z3Node, dest.z3Node, traverse.z3Node), self.ctx.packet)
        n = z3.Const('traversal_node_%s_%s_%s'%(src.z3Node, dest.z3Node, traverse.z3Node), self.ctx.node)
        constraints = list()
        # The packet is sent by the source
        constraints.append(z3.Exists([n], self.ctx.send(src.z3Node, n, p)))
        # And received by the destination
        constraints.append(z3.Exists([n], self.ctx.recv(n, dest.z3Node, p)))
        # But never really goes through the node we would like
        constraints.append(z3.Not(z3.Exists([n], self.ctx.recv(n, traverse.z3Node, p))))
        return TraversalConstraint (constraints, p, self.ctx)

    def CheckTraversalProperty (self, src, dest, traverse):
        """Check for whether all packets traverse a certain path"""
        constraints = self.TraversalConstraint(src, dest, traverse)
        result, model = self.CheckConstraints(constraints)
        constraints.result = result
        constraints.model = model
        return constraints

    def GroupTraversalConstraint (self, src, dest, traversal_group):
        """Check if all packets traverse through one of a group of elements"""
        class GroupTraversalConstraint (Constraints):
            def __init__ (self, constraintis, bad_packet, ctx):
                self.ctx = ctx
                self.violating_packet = bad_packet
                self.constraints = constraints
        p = z3.Const('traversal_packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        n0 = z3.Const('traversal_node0_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        n1 = z3.Const('traversal_node1_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        constraints = list()
        # The packet is sent by the source
        constraints.append(z3.Exists([n0], self.ctx.send(src.z3Node, n0, p)))
        # And received by the destination
        constraints.append(z3.Exists([n0], self.ctx.recv(n0, dest.z3Node, p)))
        # But never really goes through the nodes we would like
        constraints.append(z3.Not(z3.Exists([n0, n1], \
                z3.And(self.ctx.recv(n0, n1, p), \
                    z3.Or(map(lambda t: n1 == t.z3Node, traversal_group))))))
        return GroupTraversalConstraint (constraints, p, self.ctx)

    def CheckTraversalThroughGroup (self, src, dest, traversal_group):
        """Check if all packets traverse through one of a group of elements"""
        constraints = self.GroupTraversalConstraint(src, dest, traversal_group)
        result, model = self.CheckConstraints(constraints)
        constraints.result = result
        constraints.model = model
        return constraints
