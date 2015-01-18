from examples import LinkTraversalScaling
import z3
import time
import random
import sys
from itertools import permutations

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

iters = 5
min_size = 4
max_size = 25
def find_crossings (obj, n):
  count = 0
  tests = 0
  u = obj.check.CheckNodeTraversalProperty(obj.hosts[0], obj.hosts[1], n)
  if u.result == z3.unsat:
    count += 1
  return count

for size in xrange(min_size, max_size):
  for it in xrange(iters):
    ResetZ3()
    o = LinkTraversalScaling(size)
    start = time.time() 
    c = find_crossings(o, o.f2)
    print c
    stop = time.time()
    run0 = stop - start
    start = time.time() 
    c = find_crossings(o, o.f1)
    print c
    stop = time.time()
    run1 = stop - start
    print "%d %f %f"%(size, run0, run1)
