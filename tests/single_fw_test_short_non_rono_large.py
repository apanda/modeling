from examples import NoRonoTest
import z3
import time
import random
import sys

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

iters = 10
min_hosts = 200
max_hosts = 1000
print "host dmz_time q_time h_time total"
for hc in xrange(min_hosts, max_hosts):
  total_time = 0
  for i in xrange(iters):
    ResetZ3()
    unit = NoRonoTest(hc, hc, hc)
    start = time.time()
    for h in unit.dmz[0:1]:
      res = unit.check.CheckIsolationFlowProperty(unit.outside, h)
      assert res.result == z3.sat
    stop = time.time()
    dmz_time = stop - start

    ResetZ3()
    unit = NoRonoTest(hc, hc, hc)
    start = time.time()
    for h in unit.quarantine[0:1]:
      res = unit.check.CheckIsolationProperty(unit.outside, h)
      assert res.result == z3.unsat
    stop = time.time()
    q_time = stop - start

    ResetZ3()
    unit = NoRonoTest(hc, hc, hc)
    start = time.time()
    for h in unit.hosts[0:1]:
      res = unit.check.CheckIsolationProperty(unit.outside, h)
      res2 = unit.check.CheckIsolationFlowProperty(unit.outside, h)
      assert res.result == z3.sat and res2.result == z3.unsat
    stop = time.time()
    h_time = stop - start

    print "%d %f %f %f %f"%(hc, dmz_time, q_time, h_time, dmz_time + q_time + h_time)
      
