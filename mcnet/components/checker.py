import z3

class PropertyChecker (object):
    """Actually check for properties in the network graph etc."""
    def __init__ (self, context, network):
        self.ctx = context
        self.net = network
        self.solver = z3.Solver()
        self.constraints = list ()

    def ClearState (self):
        self.solver.reset()
        self.constraints = list()

    # TODO: Just use the NULL predicate
    def CheckIsolationProperty (self, src, dest):
        class IsolationResult (object):
            def __init__ (self, result, violating_packet, last_hop, last_time, ctx, assertions, model = None):
                self.ctx = ctx
                self.result = result
                self.violating_packet = violating_packet
                self.last_hop = last_hop
                self.model = model
                self.last_time = last_time
                self.assertions = assertions

        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        self.solver.push ()
        self.AddConstraints()
        p = z3.Const('check_isolation_p_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        n_0 = z3.Const('check_isolation_n_0_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        n_1 = z3.Const('check_isolation_n_1_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        t = z3.Int('check_isolation_t_%s_%s'%(src.z3Node, dest.z3Node))
        self.solver.add(self.ctx.recv(n_0, dest.z3Node, p, t))
        self.solver.add(self.ctx.send(src.z3Node, n_1, p, t))
        self.solver.add(self.ctx.nodeHasAddr(src.z3Node, self.ctx.packet.src(p)))
        self.solver.add(self.ctx.packet.origin(p) == src.z3Node)
        result = self.solver.check()
        model = None
        assertions = self.solver.assertions()
        if result == z3.sat:
            model = self.solver.model()
        self.solver.pop()
        return IsolationResult(result, p, n_0, t, self.ctx, assertions, model)

    def AssertionsToHTML (self, stream, obj):
        old = z3.in_html_mode()
        z3.set_html_mode()
        print >>stream, """
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="https://www.cs.berkeley.edu/~apanda/bootstrap/css/bootstrap.css"></link>
<link rel="stylesheet" href="https://www.cs.berkeley.edu/~apanda/bootstrap/css/bootstrap-responsive.css"></link>
<link rel="stylesheet" href="https://www.cs.berkeley.edu/~apanda/FortAwesome/css/font-awesome.min.css"></link>
<link href='https://fonts.googleapis.com/css?family=Raleway:600' rel='stylesheet' type='text/css'></link>
<title>Assertions</title>
</head>
<body style="font-size:12px">
        """
        for assertion in obj.assertions:
            print >>stream, z3.obj_to_string(assertion)
            print >>stream, "<br />"
        print >>stream, """
</body>
</html>
        """
        z3.set_html_mode(old)

    def ModelToHTML (self, stream, obj):
        old = z3.in_html_mode()
        z3.set_html_mode()
        print >>stream, """
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="https://www.cs.berkeley.edu/~apanda/bootstrap/css/bootstrap.css"></link>
<link rel="stylesheet" href="https://www.cs.berkeley.edu/~apanda/bootstrap/css/bootstrap-responsive.css"></link>
<link rel="stylesheet" href="https://www.cs.berkeley.edu/~apanda/FortAwesome/css/font-awesome.min.css"></link>
<link href='https://fonts.googleapis.com/css?family=Raleway:600' rel='stylesheet' type='text/css'></link>
<title>Model</title>
</head>
<body style="font-size:12px">
        """
        #print >>stream, z3.obj_to_string(obj.model)
        model = obj.model
        for clause in model:
            print >>stream, "%s = %s <br />"%(z3.obj_to_string(clause), z3.obj_to_string(model[clause]))
        print >>stream, """
</body>
</html>
        """
        z3.set_html_mode(old)

    ## TODO: Convert to a predicate used by CheckImpliedIsolation
    #def CheckImpliedIsolation (self, srcn, destn, src, dest):
        #class ImpliedIsolationResult (object):
            #def __init__ (self, result, violating_packet, last_hop, implied_packet, implied_last_hop, ctx, model = None):
                #self.ctx = ctx
                #self.result = result
                #self.violating_packet = violating_packet
                #self.last_hop = last_hop
                #self.implied_packet = implied_packet
                #self.implied_last_hop = implied_last_hop
                #self.model = model

        #assert(srcn in self.net.elements)
        #assert(destn in self.net.elements)
        #self.solver.push()
        #self.AddConstraints()
        #pn = z3.Const('__implied_reachability_neg_Packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        #ehn = z3.Const('__implied_reachability_neg_last_Node_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        #p = z3.Const('__implied_reachability_Packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        #eh = z3.Const('__implied_reachability_last_Node_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        #self.solver.add(z3.And(z3.Not(z3.Exists([pn, ehn], \
                               #z3.And(self.ctx.recv(ehn, destn.z3Node, pn), \
                                       #self.ctx.packet.origin(pn) == srcn.z3Node))),
                               #z3.And(z3.Exists([eh], \
                                       #self.ctx.recv(eh, dest.z3Node, p)), \
                                       #self.ctx.packet.origin(p) == src.z3Node)))
        #result = self.solver.check()
        #model = None
        #if result == z3.sat:
            #model = self.solver.model ()
        #self.solver.pop()
        #return ImpliedIsolationResult(result, p, eh, pn, ehn, self.ctx, model)

    #def CheckIsolatedIf (self, predicate, src, dest):
        #"""Check for isolation given a predicate on the packet"""
        #class IsolationResult (object):
            #def __init__ (self, result, violating_packet, last_hop, ctx, model = None):
                #self.ctx = ctx
                #self.result = result
                #self.violating_packet = violating_packet
                #self.last_hop = last_hop
                #self.model = model

        #assert(src in self.net.elements)
        #assert(dest in self.net.elements)
        #self.solver.push()
        #self.AddConstraints()
        #p = z3.Const('__reachability_Packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        #eh = z3.Const('__reachability_last_Node_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        #self.solver.add(z3.Exists([eh], z3.And(predicate(p), \
                                #self.ctx.recv(eh, dest.z3Node, p))))
        #self.solver.add(self.ctx.packet.origin(p) == src.z3Node)
        #result = self.solver.check()
        #model = None
        #if result == z3.sat:
            #model = self.solver.model ()
        #self.solver.pop()
        #return IsolationResult (result, p, eh, self.ctx, model)

    #def CheckTraversalProperty (self, src, dest, traverse):
        #"""Check that packets from src to destination always traverse the box traverse"""
        #class TraversalResult (object):
            #def __init__ (self, result, bad_packet, ctx, model = None):
                #self.ctx = ctx
                #self.model = model
                #self.result = result
                #self.violating_packet = bad_packet

        ## We want these to be in the path. Checking properties for an unreachable thing are well kind of strange.
        #assert(src in self.net.elements)
        #assert(dest in self.net.elements)
        #assert(traverse in self.net.elements)

        #self.AddConstraints()
        #self.solver.push()
        #p = z3.Const('traversal_packet_%s_%s_%s'%(src.z3Node, dest.z3Node, traverse.z3Node), self.ctx.packet)
        #n = z3.Const('traversal_node_%s_%s_%s'%(src.z3Node, dest.z3Node, traverse.z3Node), self.ctx.node)
        ## The packet is sent by the source
        #self.solver.add(z3.Exists([n], self.ctx.send(src.z3Node, n, p)))
        ## And received by the destination
        #self.solver.add(z3.Exists([n], self.ctx.recv(n, dest.z3Node, p)))
        ## But never really goes through the node we would like
        #self.solver.add(z3.Not(z3.Exists([n], self.ctx.recv(n, traverse.z3Node, p))))
        #result = self.solver.check()
        #model = None
        #if result == z3.sat:
            #model = self.solver.model ()
        #self.solver.pop()
        #return TraversalResult (result, p, self.ctx, model)

    #def CheckTraversalThroughGroup (self, src, dest, traversal_group):
        #"""Check if all packets traverse through one of a group of elements"""
        #class TraversalResult (object):
            #def __init__ (self, result, bad_packet, ctx, model = None):
                #self.ctx = ctx
                #self.model = model
                #self.result = result
                #self.violating_packet = bad_packet

        ## We want these to be in the path. Checking properties for an unreachable thing are well kind of strange.
        #assert(src in self.net.elements)
        #assert(dest in self.net.elements)
        #for t in traversal_group:
            #assert(t in self.net.elements)

        #self.solver.push()
        #self.AddConstraints()
        #p = z3.Const('traversal_packet_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        #n0 = z3.Const('traversal_node0_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        #n1 = z3.Const('traversal_node1_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        ## The packet is sent by the source
        #self.solver.add(z3.Exists([n0], self.ctx.send(src.z3Node, n0, p)))
        ## And received by the destination
        #self.solver.add(z3.Exists([n0], self.ctx.recv(n0, dest.z3Node, p)))
        ## But never really goes through the nodes we would like
        #self.solver.add(z3.Not(z3.Exists([n0, n1], \
                #z3.And(self.ctx.recv(n0, n1, p), \
                    #z3.Or(map(lambda t: n1 == t.z3Node, traversal_group))))))
        #result = self.solver.check()
        #model = None
        #if result == z3.sat:
            #model = self.solver.model ()
        #self.solver.pop()
        #return TraversalResult (result, p, self.ctx, model)

    #def AddExternalConstraints (self, constraints):
        #self.solver.push ()
        #self.solver.add (constraints)

    #def ClearExternalConstraints (self):
        #self.ClearState()

    def AddConstraints (self):
        self.ctx._addConstraints(self.solver)
        self.net._addConstraints(self.solver)
        for el in self.net.elements:
            el._addConstraints(self.solver)

    def PrintTimeline (self, ret):
        print '\n'.join(map(lambda l: str('(%s, %s, %s) -> %s'%(l[0], l[1], l[2], l[3])), \
               sorted(ret.model[ret.model[ret.ctx.etime].else_value().decl()].as_list()[:-1], \
               key=lambda l: l[-1].as_long())))
