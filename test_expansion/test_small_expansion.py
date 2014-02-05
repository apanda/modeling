from subgraphs import Subgraph01, ReseedZ3 
from mcnet.components import FindSubgraph
import sys
iters = 1
if len(sys.argv) > 1:
    iters = int(sys.argv[1])
for i in xrange(iters):
    ReseedZ3 ()
    p = Subgraph01 ()
    components = FindSubgraph(p)
    print ' '.join(map(str, map(lambda n: n.z3Node, components)))
    
