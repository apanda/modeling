from examples import PolicyScaleNeg
import z3
from z3 import is_true, is_false
import time
import mcnet.components as components
import random
import sys
def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))
iters = 5
bad_in_row = 0
for sz in xrange(2, 500):
    times = []
    all_bad = True
    for it in xrange(0, iters):
        bad = False
        ResetZ3()
        pobj = PolicyScaleNeg(sz)
        start = time.time()
        ret = pobj.check.CheckIsolationProperty(pobj.a, pobj.b)
        stop = time.time()
        if z3.unsat != ret.result:
            bad = True
        if not bad:
            times.append(stop - start)
            all_bad = False
    print "%d %s %s"%(sz, ' '.join(map(str, times)), "bad" if all_bad else "good")
    if all_bad:
        bad_in_row += 1
    else:
        bad_in_row = 0
    assert bad_in_row <= 5, \
            "Too many failures"
