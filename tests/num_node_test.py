import z3
from z3 import is_true, is_false
from examples import *
import time
import mcnet.components as components
"""Check time as increase in nodes"""
def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()

for it in xrange(0, 10):
    ResetZ3()
    for sz in xrange(2, 100):
        start = time.time()
        obj = NumNodesTest (sz)
        # Set timeout to some largish number
        obj.check.solver.set(timeout=1000000)
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

