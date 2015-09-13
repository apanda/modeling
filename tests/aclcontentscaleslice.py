import z3
from examples import NAclContentCacheScaleTestFP, AclContentCacheScaleTestFP

import time
#import mcnet.components as components
import random
import sys
import argparse

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', 42)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'Slice ACL Content scale')
    parser.add_argument('--min', type=int, nargs='?', default=20)
    parser.add_argument('--max', type=int, nargs='?', default=100)
    parser.add_argument('--iters', type=int, nargs='?', default=5)
    args = parser.parse_args()
    iters = args.iters 
    start_size = args.min
    stop_size = args.max
    print 'size RCCA RNCCA'
    for it in xrange(iters):
        for size in xrange(start_size, stop_size):
          ResetZ3()
          model = AclContentCacheScaleTestFP(size)
          start = time.time()
          res = model.check.CheckDataIsolationProperty(model.s0, model.endhosts[1])
          stop = time.time()
          assert(res.result == z3.sat)
          unsat_time = stop - start
          start = time.time()
          res = model.check.CheckDataIsolationProperty(model.s0, model.endhosts[0])
          stop = time.time()
          assert(res.result == z3.unsat)
          sat_time = stop - start

          ResetZ3()
          model = NAclContentCacheScaleTestFP(size)
          start = time.time()
          res = model.check.CheckDataIsolationProperty(model.s0, model.endhosts[1])
          stop = time.time()
          assert(res.result == z3.sat)
          unsat_time2 = stop - start
          start = time.time()
          res = model.check.CheckDataIsolationProperty(model.s0, model.endhosts[0])
          stop = time.time()
          assert(res.result == z3.sat)
          sat_time2 = stop - start
          print '%d %f %f'%(size, unsat_time + sat_time, unsat_time2 + sat_time2)
