import z3
from examples import AclContentCacheScaleTest
import time
import mcnet.components as components
import random
import sys

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', 42)

iters = 5
start_size = 20
stop_size = 100
print 'size sat unsat'
for size in xrange(start_size, stop_size):
    for it in xrange(iters):
      ResetZ3()
      model = AclContentCacheScaleTest(size)
      start = time.time()
      res = model.check.CheckDataIsolationProperty(model.s1, model.endhosts[1])
      stop = time.time()
      unsat_time = stop - start
      start = time.time()
      res = model.check.CheckDataIsolationProperty(model.s1, model.endhosts[0])
      stop = time.time()
      sat_time = stop - start
      print '%d %f %f'%(size, unsat_time, sat_time)
