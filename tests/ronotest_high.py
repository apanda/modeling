import z3
from examples import permuteTest 
import time
import mcnet.components as components
import random
import sys

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

print "size ctime time result"
for it in xrange(0, 20):
    for size in xrange(100, 500):
        ResetZ3()
        start = time.time()
        t = permuteTest(size)
        stop = time.time()
        const_time = stop - start
        start = time.time()
        r = t.check.CheckIsolationProperty(t.a, t.b)
        stop = time.time()
        print "%d %f %f %s"%(size, const_time, stop - start, r.result)
