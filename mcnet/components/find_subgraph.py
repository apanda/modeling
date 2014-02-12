import z3
from find_subgraph_problem import SubgraphProblem
from . import CheckIsPathIndependentIsolatedTime, \
              PropertyChecker, \
              VERIFIED_ISOLATION, \
              VERIFIED_GLOBAL, \
              UNKNOWN
import random
import sys
def ResetZ3Perf ():
    global z3
    z3 = reload(z3)
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('auto_config', False)
    z3.set_param('smt.mbqi', True)
    z3.set_param('model.compact', True)
    z3.set_param('smt.pull_nested_quantifiers', True)
    z3.set_param('smt.mbqi.max_iterations', 10000)
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

def ReseedZ3 ():
    global z3
    z3 = reload(z3)
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

def ResetZ3 ():
    global z3
    z3 = reload(z3)
    z3._main_ctx = None
    z3.main_ctx()

"""The actual solver for the find_subgraph problem. problem is a function returning a SubgraphProblem"""
def FindSubgraph (problem):
    print "Starting out"

    prob = problem()
    isolation_map = GetIsolationMap(prob)
    for k, v in isolation_map.iteritems():
        print "%s: %s"%(k, ' '.join(v))

    active_nodes = [prob.origin, prob.target]

    while len(active_nodes) < len(prob.node_map.keys()):
        ReseedZ3 ()
        prob = problem ()
        curr_net = prob.network

        for element in prob.tfunctions.iterkeys():
            curr_net.RoutingTable(prob.node_map[element], prob.tfunctions[element])
            curr_net.SetIsolationConstraint(prob.node_map[element], map(lambda n: prob.node_map[n], isolation_map[element]))
        print "Attaching %s"%(' '.join(map(str, map(lambda n: prob.node_map[n].z3Node, active_nodes))))
        curr_net.Attach(*map(lambda n: prob.node_map[n], active_nodes))
        solver = PropertyChecker (prob.ctx, curr_net)
        ret = CheckIsPathIndependentIsolatedTime (solver,  \
                                           prob.node_map[prob.origin], \
                                           prob.node_map[prob.target], \
                                           map(lambda n: prob.node_map[n], active_nodes))

        if ret.judgement == VERIFIED_ISOLATION:
            print "We verified that the model was good the result was %s"%(ret.overapprox_result.result)
            if ret.overapprox_result.result != z3.unsat:
                print "Over approx model"
                solver.PrintRecv(ret.overapprox_result)
                print
                solver.PrintTimeline(ret.overapprox_result)
                if ret.underapprox_result:
                    print "Under approx model"
                    solver.PrintRecv(ret.underapprox_result)
                    print
                    solver.PrintTimeline(ret.underapprox_result)
            break
        else:
            print "We verified that the model was not good the result was %s"%(ret.overapprox_result.result)
            if ret.overapprox_result.result != z3.unsat:
                print "Over approx model"
                solver.PrintRecv(ret.overapprox_result)
                print
                solver.PrintTimeline(ret.overapprox_result)
        assert(ret.judgement != UNKNOWN)
        # Figure out a way to add things
        model = ret.overapprox_result.model
        edges = GetCrossingEdges(prob.ctx, model, active_nodes, prob)
        elements = map(str, [node for edge in edges for node in edge])
        elements = set(elements)
        new_elements = set(elements) - set(active_nodes)
        active_nodes.extend(list(new_elements))

    if len(active_nodes) == len(prob.node_map.keys()):
        print "Found the entire graph"
    return active_nodes

def GetCrossingEdges (ctx, model, active_nodes, prob):
    recv_packets = model[model[ctx.recv].else_value().decl()].as_list()[:-1]
    edges = map(lambda a: (a[0], a[1]), recv_packets)
    def crossing_filter (edge):
        # The != below is an XOR operator. Yes this is stupid
        return any(map(lambda n: z3.is_true(model.eval(edge[0] == prob.node_map[n].z3Node)), active_nodes)) != \
        any(map(lambda n: z3.is_true(model.eval(edge[1] == prob.node_map[n].z3Node)), active_nodes))
    crossing_edges = filter(crossing_filter, edges)
    return crossing_edges

def GetIsolationMap (prob):
    isolation_constraints = {}
    for k in prob.tfunctions.iterkeys():
        isolation_constraints[k] = map(lambda (p, n): str(n.z3Node), prob.tfunctions[k])
    for k, v in isolation_constraints.iteritems():
        for n in v:
            isolation_constraints[n].append(k)
    real_isolation_constraints = {}
    for k, v in isolation_constraints.iteritems():
        real_isolation_constraints[k] = list(set(v))
    return real_isolation_constraints
