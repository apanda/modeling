from examples import NoRonoTest
import z3
import time
import random
import sys

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

iters = 2
min_hosts = 5
max_hosts = 100
print "host iter dmz_time q_time h_time"
for h in xrange(min_hosts, max_hosts, 5):
  for i in xrange(iters):
    try:
      dmz_time = 0.0
      ResetZ3()
      dmz = NoRonoTest(h, h, h)
      start = time.time()
      res = dmz.check.CheckIsolationFlowProperty(dmz.outside, dmz.dmz[0])
      assert res.result == z3.sat
      stop = time.time()
      dmz_time += (stop - start)
    except:
      dmz_time = '*'

    try:
      q_time = 0.0
      ResetZ3()
      quarantine = NoRonoTest(h, h, h)
      start = time.time()
      res = quarantine.check.CheckIsolationProperty(quarantine.outside, quarantine.quarantine[0])
      assert res.result == z3.unsat
      stop = time.time()
      q_time += (stop - start)
    except:
      q_time = '*'

    try:
      h_time = 0.0
      ResetZ3()
      host = NoRonoTest(h, h, h)
      start = time.time()
      res = host.check.CheckIsolationProperty(host.outside, host.hosts[0])
      res2 = host.check.CheckIsolationFlowProperty(host.outside, host.hosts[0])
      assert res.result == z3.sat and res2.result == z3.unsat
      stop = time.time()
      h_time += (stop - start)
    except:
      h_time = '*'
      raise
    print h, i, dmz_time, q_time, h_time 
      
