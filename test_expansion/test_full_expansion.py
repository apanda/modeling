from subgraphs import Subgraph01, ReseedZ3, ResetZ3
from mcnet.components import CheckIsPathIndependentIsolatedTime, PropertyChecker
import sys
import time
iters = 1
if len(sys.argv) > 1:
    iters = int(sys.argv[1])
for i in xrange(iters):
    ReseedZ3()
    start = time.time()
    prob = Subgraph01()
    curr_net = prob.network
    active_nodes = ['a', 'g', 'b', 'f0']
    for element in active_nodes:
        print "Routing table for %s"%(element)
        curr_net.RoutingTable(prob.node_map[element], prob.tfunctions[element])
    print "Attaching %s"%(' '.join(map(str, map(lambda n: prob.node_map[n].z3Node, active_nodes))))
    curr_net.Attach(*map(lambda n: prob.node_map[n], active_nodes))
    solver = PropertyChecker (prob.ctx, curr_net)
    ret = CheckIsPathIndependentIsolatedTime (solver,  \
                                       prob.node_map[prob.origin], \
                                       prob.node_map[prob.target], \
                                       map(lambda n: prob.node_map[n], active_nodes))
    stop = time.time()
    print ret.judgement
    print 'TIME TAKEN = %f'%(stop - start)
    
