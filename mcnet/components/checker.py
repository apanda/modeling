import z3
import collections

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

    def CheckIsolationProperty (self, src, dest, packet_constraint = None):
        class IsolationResult (object):
            def __init__ (self, result, violating_packet, last_hop, last_send_time, last_recv_time, ctx, assertions, model = None):
                self.ctx = ctx
                self.result = result
                self.violating_packet = violating_packet
                self.last_hop = last_hop
                self.model = model
                self.last_send_time = last_send_time
                self.last_recv_time = last_recv_time
                self.assertions = assertions

        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        self.solver.push ()
        self.AddConstraints()
        p = z3.Const('check_isolation_p_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        n_0 = z3.Const('check_isolation_n_0_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        n_1 = z3.Const('check_isolation_n_1_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        t_0 = z3.Int('check_isolation_t0_%s_%s'%(src.z3Node, dest.z3Node))
        t_1 = z3.Int('check_isolation_t1_%s_%s'%(src.z3Node, dest.z3Node))
        self.solver.add(self.ctx.recv(n_0, dest.z3Node, p, t_0))
        self.solver.add(self.ctx.send(src.z3Node, n_1, p, t_1))
        self.solver.add(self.ctx.nodeHasAddr(src.z3Node, self.ctx.packet.src(p)))
        self.solver.add(self.ctx.packet.origin(p) == src.z3Node)
        if packet_constraint:
            self.solver.add(packet_constraint(p))
        result = self.solver.check()
        model = None
        assertions = self.solver.assertions()
        if result == z3.sat:
            model = self.solver.model()
        self.solver.pop()
        return IsolationResult(result, p, n_0, t_1, t_0, self.ctx, assertions, model)

    def CheckIsolationPropertyCore (self, src, dest):
        class IsolationResult (object):
            def __init__ (self, result, violating_packet, last_hop, last_send_time, last_recv_time, ctx, assertions,\
                    model, inv_model):
                self.ctx = ctx
                self.result = result
                self.violating_packet = violating_packet
                self.last_hop = last_hop
                self.model = model
                self.inv_model = inv_model
                self.last_send_time = last_send_time
                self.last_recv_time = last_recv_time
                self.assertions = assertions

        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        self.solver.push ()
        constraints = self.GetConstraints()
        #self.AddConstraints()
        p = z3.Const('check_isolation_p_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        n_0 = z3.Const('check_isolation_n_0_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        n_1 = z3.Const('check_isolation_n_1_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        t_0 = z3.Int('check_isolation_t0_%s_%s'%(src.z3Node, dest.z3Node))
        t_1 = z3.Int('check_isolation_t1_%s_%s'%(src.z3Node, dest.z3Node))
        constraints.append(self.ctx.recv(n_0, dest.z3Node, p, t_0))
        constraints.append(self.ctx.send(src.z3Node, n_1, p, t_1))
        constraints.append(self.ctx.nodeHasAddr(src.z3Node, self.ctx.packet.src(p)))
        constraints.append(self.ctx.packet.origin(p) == src.z3Node)

        names = []
        for constraint in constraints:
            n = z3.Bool('%s'%constraint)
            names += [n]
            self.solver.add(z3.Implies(n, constraint))
        is_sat = self.solver.check(names)
        ret = None
        if is_sat == z3.sat:
            print "SAT"
            ret =  IsolationResult(is_sat,p, n_0, t_1, t_0, self.ctx, self.solver.assertions(), self.solver.model(),
                    None)
        elif is_sat == z3.unsat:
            print "unsat"
            ret =  IsolationResult(is_sat,p, n_0, t_1, t_0, self.ctx, self.solver.assertions(),
                    self.solver.unsat_core(), None)
        self.solver.pop()
        self.solver.push ()

        constraints = self.GetConstraints()
        constraints.append(self.ctx.send(src.z3Node, n_1, p, t_1))
        constraints.append(z3.Not(self.ctx.recv(n_0, dest.z3Node, p, t_0)))
        constraints.append(self.ctx.nodeHasAddr(src.z3Node, self.ctx.packet.src(p)))
        constraints.append(self.ctx.packet.origin(p) == src.z3Node)

        names = []
        for constraint in constraints:
            n = z3.Bool('%s'%constraint)
            names += [n]
            self.solver.add(z3.Implies(n, constraint))
        is_sat = self.solver.check(names)
        if is_sat == z3.sat:
            print "SAT"
            ret.inv_model = self.solver.model()
        elif is_sat == z3.unsat:
            print "unsat"
            ret.inv_model = self.solver.unsat_core()
        self.solver.pop()
        
        return ret

    def CheckIsolationFlowProperty (self, src, dest, packet_constraint = None):
        class IsolationResult (object):
            def __init__ (self, result, violating_packet, last_hop, last_send_time, last_recv_time, ctx, assertions, model = None):
                self.ctx = ctx
                self.result = result
                self.violating_packet = violating_packet
                self.last_hop = last_hop
                self.model = model
                self.last_send_time = last_send_time
                self.last_recv_time = last_recv_time
                self.assertions = assertions

        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        self.solver.push ()
        self.AddConstraints()
        p = z3.Const('check_isolation_p_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        n_0 = z3.Const('check_isolation_n_0_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        n_1 = z3.Const('check_isolation_n_1_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        n_2 = z3.Const('check_isolation_n_2_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        t_0 = z3.Int('check_isolation_t0_%s_%s'%(src.z3Node, dest.z3Node))
        t_1 = z3.Int('check_isolation_t1_%s_%s'%(src.z3Node, dest.z3Node))
        t_2 = z3.Int('check_isolation_t2_%s_%s'%(src.z3Node, dest.z3Node))
        self.solver.add(self.ctx.recv(n_0, dest.z3Node, p, t_0))
        self.solver.add(self.ctx.send(src.z3Node, n_1, p, t_1))
        self.solver.add(self.ctx.nodeHasAddr(src.z3Node, self.ctx.packet.src(p)))
        self.solver.add(self.ctx.packet.origin(p) == src.z3Node)
        p_2 = z3.Const('check_isolation_p_flow_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        self.solver.add(z3.Not(z3.Exists([p_2, n_2, t_2], \
                z3.And(self.ctx.send(dest.z3Node, n_2, p_2, t_2), \
                       self.ctx.packet.src(p_2) == self.ctx.packet.dest(p), \
                       self.ctx.src_port(p_2) == self.ctx.dest_port(p), \
                       self.ctx.dest_port(p_2) == self.ctx.src_port(p), \
                       self.ctx.packet.dest(p_2) == self.ctx.packet.src(p), \
                       t_2 < t_0))))
        if packet_constraint:
            self.solver.add(packet_constraint(p))
        result = self.solver.check()
        model = None
        assertions = self.solver.assertions()
        if result == z3.sat:
            model = self.solver.model()
        self.solver.pop()
        return IsolationResult(result, p, n_0, t_1, t_0, self.ctx, assertions, model)

    def CheckNodeTraversalProperty (self, src, dest, node):
        class IsolationResult (object):
            def __init__ (self, result, violating_packet, last_hop, last_send_time, last_recv_time, ctx, assertions, model = None):
                self.ctx = ctx
                self.result = result
                self.violating_packet = violating_packet
                self.last_hop = last_hop
                self.model = model
                self.last_send_time = last_send_time
                self.last_recv_time = last_recv_time
                self.assertions = assertions

        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        self.solver.push ()
        self.AddConstraints()
        p = z3.Const('check_isolation_p_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        n_0 = z3.Const('check_isolation_n_0_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        n_1 = z3.Const('check_isolation_n_1_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        n_2 = z3.Const('check_isolation_n_2_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        t_0 = z3.Int('check_isolation_t0_%s_%s'%(src.z3Node, dest.z3Node))
        t_1 = z3.Int('check_isolation_t1_%s_%s'%(src.z3Node, dest.z3Node))
        t_2 = z3.Int('check_isolation_t2_%s_%s'%(src.z3Node, dest.z3Node))
        self.solver.add(self.ctx.recv(n_0, dest.z3Node, p, t_0))
        self.solver.add(self.ctx.send(src.z3Node, n_1, p, t_1))
        self.solver.add(self.ctx.nodeHasAddr(src.z3Node, self.ctx.packet.src(p)))
        self.solver.add(self.ctx.packet.origin(p) == src.z3Node)
        self.solver.add(z3.Not(z3.Exists([n_2, t_2],\
            z3.And(self.ctx.recv(n_2, node.z3Node, p, t_2), \
                   t_2 < t_0))))
        self.solver.add(z3.Not(z3.Exists([n_2, t_2],\
            z3.And(self.ctx.send(node.z3Node, n_2, p, t_2), \
                   t_2 < t_0))))
        result = self.solver.check()
        model = None
        assertions = self.solver.assertions()
        if result == z3.sat:
            model = self.solver.model()
        self.solver.pop()
        return IsolationResult(result, p, n_0, t_1, t_0, self.ctx, assertions, model)

    def CheckLinkTraversalProperty (self, src, dest, le0, le1):
        class IsolationResult (object):
            def __init__ (self, result, violating_packet, last_hop, last_send_time, last_recv_time, ctx, assertions, model = None):
                self.ctx = ctx
                self.result = result
                self.violating_packet = violating_packet
                self.last_hop = last_hop
                self.model = model
                self.last_send_time = last_send_time
                self.last_recv_time = last_recv_time
                self.assertions = assertions

        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        self.solver.push ()
        self.AddConstraints()
        p = z3.Const('check_isolation_p_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        n_0 = z3.Const('check_isolation_n_0_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        n_1 = z3.Const('check_isolation_n_1_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        n_2 = z3.Const('check_isolation_n_2_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        t_0 = z3.Int('check_isolation_t0_%s_%s'%(src.z3Node, dest.z3Node))
        t_1 = z3.Int('check_isolation_t1_%s_%s'%(src.z3Node, dest.z3Node))
        t_2 = z3.Int('check_isolation_t2_%s_%s'%(src.z3Node, dest.z3Node))
        self.solver.add(self.ctx.recv(n_0, dest.z3Node, p, t_0))
        self.solver.add(self.ctx.send(src.z3Node, n_1, p, t_1))
        self.solver.add(self.ctx.nodeHasAddr(src.z3Node, self.ctx.packet.src(p)))
        self.solver.add(self.ctx.packet.origin(p) == src.z3Node)
        self.solver.add(\
           z3.Or(z3.Exists([t_1, t_2], z3.And(self.ctx.send(le0.z3Node, le1.z3Node, p, t_1), \
                        self.ctx.recv(le0.z3Node, le1.z3Node, p, t_2), \
                        t_1 < t_0, \
                        t_2 < t_0))))
                 #z3.And(self.ctx.send(le1.z3Node, le0.z3Node, p, t_1), \
                        #self.ctx.recv(le1.z3Node, le0.z3Node, p, t_2), \
                        #t_2 < t_0, \
                        #t_1 < t_0)))
        result = self.solver.check()
        model = None
        assertions = self.solver.assertions()
        if result == z3.sat:
            model = self.solver.model()
        self.solver.pop()
        return IsolationResult(result, p, n_0, t_1, t_0, self.ctx, assertions, model)

    def CheckDataIsolationPropertyCore (self, src, dest):
        class Result(object):
            def __init__ (self, core):
                self.assertions = core
        assert(src in self.net.elements)
        assert(dest in self.net.elements)
        constraints = self.GetConstraints()
        p = z3.Const('check_isolation_p_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.packet)
        n_0 = z3.Const('check_isolation_n_0_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        n_1 = z3.Const('check_isolation_n_1_%s_%s'%(src.z3Node, dest.z3Node), self.ctx.node)
        t = z3.Int('check_isolation_t_%s_%s'%(src.z3Node, dest.z3Node))

        constraints.append(self.ctx.recv(n_0, dest.z3Node, p, t))
        constraints.append(self.ctx.packet.origin(p) == src.z3Node)
        print constraints
        self.solver.push ()
        names = []
        for constraint in constraints:
            n = z3.Bool('%s'%constraint)
            names += [n]
            self.solver.add(z3.Implies(n, constraint))
        is_sat = self.solver.check(names)
        ret = None
        if is_sat == z3.sat:
            print "SAT"
            ret =  Result(self.solver.model())
        elif is_sat == z3.unsat:
            print "unsat"
            ret = Result(self.solver.unsat_core())
        self.solver.pop()
        return ret

    def CheckDataIsolationProperty (self, src, dest):
        class DataIsolationResult (object):
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
        self.solver.add(self.ctx.packet.origin(p) == src.z3Node)
        result = self.solver.check()
        model = None
        assertions = self.solver.assertions()
        if result == z3.sat:
            model = self.solver.model()
        self.solver.pop()
        return DataIsolationResult(result, p, n_0, t, self.ctx, assertions, model)

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

    def GetConstraints (self):
        class Temp(object):
            def __init__(self):
                self.infra_constraints = []
                self.policy_constraints = []
            def add(self, constraints):
                if isinstance(constraints, collections.Iterable):
                    self.infra_constraints.extend(constraints)
                else:
                    self.infra_constraints.append(constraints)
        l = Temp()
        self.ctx._addConstraints(l)
        self.net._addConstraints(l)
        for el in self.net.elements:
            el._addConstraints(l)
        return l.infra_constraints

    def AddConstraints (self):
        self.ctx._addConstraints(self.solver)
        self.net._addConstraints(self.solver)
        for el in self.net.elements:
            el._addConstraints(self.solver)

    def PrintTimeline (self, ret):
        print '\n'.join(map(lambda l: str('(%s, %s, %s) -> %s'%(l[0], l[1], l[2], l[3])), \
               sorted(ret.model[ret.model[ret.ctx.etime].else_value().decl()].as_list()[:-1], \
               key=lambda l: l[-1].as_long())))
