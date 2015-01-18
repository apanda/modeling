import z3
from examples import AclContentCacheScaleTestFP
import time
import mcnet.components as components
import random
import sys

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

iters = 5
start_size = 20
stop_size = 100
print 'size sat unsat'
for size in xrange(start_size, stop_size):
    for it in xrange(iters):
      ResetZ3()
      model = AclContentCacheScaleTestFP(size)
      start = time.time()
      res = model.check.CheckDataIsolationProperty(model.s1, model.endhosts[1])
      stop = time.time()
      unsat_time = stop - start
      start = time.time()
      res = model.check.CheckDataIsolationProperty(model.s1, model.endhosts[0])
      stop = time.time()
      sat_time = stop - start
      print '%d %f %f'%(size, unsat_time, sat_time)
#print "size ctime time result rono_ctime rono_time rono_result"
#for it in xrange(1, 20):
    #for size in xrange(0, 100):
        #ResetZ3()
        #start = time.time()
        #t = permuteTest(size)
        #stop = time.time()
        #const_time = stop - start
        #start = time.time()
        #r = t.check.CheckIsolationProperty(t.a, t.b)
        #stop = time.time()
        #nrtime = stop - start
        #ResetZ3()
        #start = time.time()
        #t2 = permuteTest(0)
        #stop = time.time()
        #const_time_rono = stop - start
        #start = time.time()
        #r2 = t2.check.CheckIsolationProperty(t2.a, t2.b)
        #stop = time.time()
        #rtime = stop - start
        #print "%d %f %f %s %f %f %s"%(size, const_time, nrtime, r.result, const_time_rono, rtime, r2.result)
