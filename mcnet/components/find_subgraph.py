import z3
from find_subgraph_problem import SubgraphProblem
from . import CheckIsPathIndependentIsolatedTime, \
              PropertyChecker, \
              VERIFIED_ISOLATION, \
              VERIFIED_GLOBAL, \
              UNKNOWN
"""The actual solver for the find_subgraph problem"""
def FindSubgraph (problem):
    print "Starting out"
    active_nodes = [problem.origin, problem.target]
    curr_net = problem.network.Copy()
    curr_net.Attach(*active_nodes)
    solver = PropertyChecker (problem.ctx, curr_net)
    curr_net.RoutingTable(problem.origin, problem.tfunctions[str(problem.origin.z3Node)])
    curr_net.RoutingTable(problem.target, problem.tfunctions[str(problem.target.z3Node)])
    while len(active_nodes) < len(problem.node_map.keys()):
        print "Checking active_nodes are %s"%(' '.join(map(str, map(lambda n: n.z3Node, active_nodes))))
        ret = CheckIsPathIndependentIsolatedTime (solver,  \
                                           problem.origin, \
                                           problem.target, \
                                           active_nodes)
        if ret.judgement == VERIFIED_ISOLATION:
            break
        assert(ret.judgement != UNKNOWN)
        # Figure out a way to add things
        model = ret.overapprox_result.model
        edges = GetCrossingEdges(problem.ctx, model, active_nodes)
        elements = map(str, [node for edge in edges for node in edge])
        elements = set(elements)
        new_elements = set(elements) - set(map(str, map(lambda n:n.z3Node, active_nodes)))
        active_nodes.extend(map(lambda n: problem.node_map[n], list(new_elements)))
        for element in new_elements:
            curr_net.RoutingTable(problem.node_map[element], problem.tfunctions[element])
    if len(active_nodes) == len(problem.node_map.keys()):
        print "Found the entire graph"
    return active_nodes
def GetCrossingEdges (ctx, model, active_nodes):
    recv_packets = model[model[ctx.recv].else_value().decl()].as_list()[:-1]
    edges = map(lambda a: (a[0], a[1]), recv_packets)
    def crossing_filter (edge):
        # The != below is an XOR operator. Yes this is stupid
        return any(map(lambda n: z3.is_true(model.eval(edge[0] == n.z3Node)), active_nodes)) != \
        any(map(lambda n: z3.is_true(model.eval(edge[1] == n.z3Node)), active_nodes))
    crossing_edges = filter(crossing_filter, edges)
    return crossing_edges
