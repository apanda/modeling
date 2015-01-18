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
  for (ha, hb) in permutations(obj.hosts, 2):
    u = obj.check.CheckNodeTraversalProperty(ha, hb, n)
    if u.result == z3.sat:
      count += 1
    tests+=1
  return (count, tests)

for size in xrange(min_size, max_size):
  for it in xrange(iters):
    ResetZ3()
    o = LinkTraversalScaling(size)
    start = time.time() 
    (c, t) = find_crossings(o, o.f2)
    stop = time.time()
    print "%d %d %d %f"%(size, t, c, (stop - start))
