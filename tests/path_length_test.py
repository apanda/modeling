import z3
from z3 import is_true, is_false
from examples import *
import time
import mcnet.components as components
"""Check time as pure increase in path length"""
def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()

for sz in xrange(1, 20):
    ResetZ3()
    start = time.time()
    obj = PathLengthTest (sz)
    # Set timeout to some largish number
    obj.check.solver.set(timeout=10000000)
    ret = obj.check.CheckIsolationProperty(obj.e_0, obj.e_1)
    assert z3.unsat == ret.result, \
            "No way to go"
    ret = obj.check.CheckIsolationProperty(obj.e_0, obj.e_2)
    assert z3.sat == ret.result, \
            "Nothing stopping this"
    ret = obj.check.CheckIsolationProperty(obj.e_0, obj.e_3)
    assert z3.sat == ret.result, \
            "Nothing stopping this"
    stop = time.time()
    print "%d %f"%(sz, stop - start)

