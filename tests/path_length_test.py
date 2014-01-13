import z3
from z3 import is_true, is_false
from examples import *
import time
import mcnet.components as components
"""Check time as pure increase in path length"""
def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('auto_config', False)
    z3.set_param('smt.mbqi', True)
    z3.set_param('model.compact', True)
    z3.set_param('smt.pull_nested_quantifiers', True)
    z3.set_param('smt.mbqi.max_iterations', 10000)

bad_in_row = 0
for sz in xrange(1, 200):
    ResetZ3()
    start = time.time()
    obj = PathLengthTest (sz)
    # Set timeout to some largish number
    obj.check.solver.set(timeout=10000000)
    ret = obj.check.CheckIsolationProperty(obj.e_0, obj.e_1)
    bad = False
    if z3.unsat != ret.result:
        bad = True
    ret = obj.check.CheckIsolationProperty(obj.e_0, obj.e_2)
    if z3.sat != ret.result:
        bad = True
    ret = obj.check.CheckIsolationProperty(obj.e_0, obj.e_3)
    if z3.sat != ret.result:
        bad = True
    stop = time.time()
    print "%d %f %s"%(sz, stop - start, "bad" if bad else "good")
    if bad:
        bad_in_row += 1
    else:
        bad_in_row = 0
    assert bad_in_row <= 5, \
            "Too many failures"

