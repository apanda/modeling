from subgraphs import Subgraph01, ReseedZ3, ResetZ3Perf 
from mcnet.components import FindSubgraph
import sys
iters = 1
if len(sys.argv) > 1:
    iters = int(sys.argv[1])
for i in xrange(iters):
    ResetZ3Perf ()
    p = Subgraph01 ()
    components = FindSubgraph(p)
    print ' '.join(map(str, map(lambda n: n.z3Node, components)))
    
