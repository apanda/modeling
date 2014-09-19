from examples import RonoDMZTest, RonoQuarantineTest, RonoHostTest
import z3
import time
import random
import sys

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

iters = 10
min_hosts = 5
max_hosts = 1000
print "host dmz_time q_time h_time total"
for h in xrange(min_hosts, max_hosts):
  total_time = 0
  for i in xrange(iters):
    ResetZ3()
    dmz = RonoDMZTest(h, h, h)
    start = time.time()
    for i in xrange(h):
      res = dmz.check.CheckIsolationFlowProperty(dmz.outside, dmz.dmz)
      assert res.result == z3.sat
    stop = time.time()
    dmz_time = stop - start

    quarantine = RonoQuarantineTest(h, h, h)
    start = time.time()
    for i in xrange(h):
      res = quarantine.check.CheckIsolationProperty(quarantine.outside, quarantine.quarantine)
      assert res.result == z3.unsat
    stop = time.time()
    q_time = stop - start

    host = RonoHostTest(h, h, h)
    start = time.time()
    for i in xrange(h):
      res = host.check.CheckIsolationProperty(host.outside, host.host)
      res2 = host.check.CheckIsolationFlowProperty(host.outside, host.host)
      assert res.result == z3.sat and res2.result == z3.unsat
    stop = time.time()
    h_time = stop - start
    print "%d %f %f %f %f"%(h, dmz_time, q_time, h_time, dmz_time + q_time + h_time)
      
