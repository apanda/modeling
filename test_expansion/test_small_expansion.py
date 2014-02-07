from subgraphs import Subgraph01, ReseedZ3, ResetZ3Perf 
from mcnet.components import FindSubgraph
import sys
import time
iters = 1
if len(sys.argv) > 1:
    iters = int(sys.argv[1])
for i in xrange(iters):
    start = time.time()
    p = Subgraph01
    components = FindSubgraph(p)
    stop = time.time()
    print 'Found subgraph:'
    print ' '.join(map(str, components))
    print 'TIME TAKEN = %f'%(stop - start)
    
