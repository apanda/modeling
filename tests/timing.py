import z3
from z3 import is_true, is_false
from examples import *
import time
import mcnet.components as components
import random
import sys

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('auto_config', False)
    z3.set_param('smt.mbqi', True)
    z3.set_param('model.compact', True)
    z3.set_param('smt.pull_nested_quantifiers', True)
    z3.set_param('smt.mbqi.max_iterations', 10000)
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))
for it in xrange(0, 100):
    for sz in xrange(2, 11):
        ResetZ3()
        start = time.time()
        obj = LSRRFwExample (sz)
        ret = obj.check.CheckIsolationProperty(obj.e0, obj.e1)
        assert z3.sat == ret.result, \
                "Satisfiable, no blocks"
        stop = time.time()
        print '%d %f'%(sz, stop - start)

