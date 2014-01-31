from concrete_examples import dpiFwRono, ReseedZ3 
from mcnet.components import CheckIsPathIndependentIsolated
import numpy as np
import sys
import time
import z3

if len(sys.argv) < 3:
    print >>sys.stderr, "Usage: %s sz iter"%(sys.argv[0])
    sys.exit(1)
sz = int(sys.argv[1])
it = int(sys.argv[2])
for i in xrange(it):
    #ReseedZ3()
    #pobj = dpiFwRono(sz)
    #print "Done building object"
    #start = time.time()
    #ret = pobj.check.CheckIsolatedIf(pobj.dpi_policy.packetDPIPredicate(pobj.ctx), pobj.a, pobj.b)
    #stop = time.time()
    #time0 = stop - start
    #assert ret.result == z3.sat
    ReseedZ3()
    pobj = dpiFwRono(sz)
    start = time.time()
    ret2 = pobj.check.CheckIsolationProperty(pobj.a, pobj.b)
    stop = time.time()
    assert ret2.result == z3.sat
    print >>sys.stderr, "%d %f %f"%(i, stop - start)

