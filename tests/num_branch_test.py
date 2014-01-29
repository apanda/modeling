import z3
from z3 import is_true, is_false
from examples import *
import time
import mcnet.components as components
import random
import sys
"""Check time as increase in nodes"""
def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('auto_config', False)
    z3.set_param('smt.mbqi', True)
    z3.set_param('model.compact', True)
    z3.set_param('smt.pull_nested_quantifiers', True)
    z3.set_param('smt.mbqi.max_iterations', 10000)
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

bad_in_row = 0
iters = 10
for sz in xrange(2, 200):
    times = []
    all_bad = True
    for it in xrange(0, iters):
        bad = False
        ResetZ3()
        obj = PolicyScaleWithBranch (1, sz)
        start = time.time()
        # Set timeout to some largish number
        obj.check.solver.set(timeout=10000000)
        ret = obj.check.CheckIsolationProperty(obj.a, obj.b)
        stop = time.time()
        if z3.sat != ret.result:
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

