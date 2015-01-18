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
max_size = 100
def find_crossings (obj, la, lb):
  count = 0
  tests = 0
  #for (ha, hb) in permutations(obj.hosts, 2):
  u = obj.check.CheckLinkTraversalProperty(obj.hosts[0], obj.hosts[1], la, lb)
  u = obj.check.CheckLinkTraversalProperty(obj.hosts[0], obj.hosts[2], la, lb)
  tests+=1
  return len(list(permutations(obj.hosts, 2)))

for size in xrange(min_size, max_size):
  for it in xrange(iters):
    ResetZ3()
    o = LinkTraversalScaling(size)
    start = time.time() 
    t = find_crossings(o, o.f0, o.f2)
    stop = time.time()
    print "%d %d %f"%(size, t, (stop - start))
