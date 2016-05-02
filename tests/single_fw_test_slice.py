from examples import RonoDMZTest, RonoQuarantineTest, RonoHostTest
import z3
import time
import random
import sys

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

iters = 100
print "dmz_time q_time h_time total"
for i in xrange(iters):
  try:
    dmz_time = 0.0
    ResetZ3()
    dmz = RonoDMZTest(1, 1, 1)
    start = time.time()
    res = dmz.check.CheckIsolationFlowProperty(dmz.outside, dmz.dmz)
    assert res.result == z3.sat
    stop = time.time()
    dmz_time += (stop - start)
  except:
    dmz_time = '*'

  try:
    q_time = 0.0
    ResetZ3()
    quarantine = RonoQuarantineTest(1, 1, 1)
    start = time.time()
    res = quarantine.check.CheckIsolationProperty(quarantine.outside, quarantine.quarantine)
    assert res.result == z3.unsat
    stop = time.time()
    q_time += (stop - start)
  except:
    q_time = '*'

  try:
    h_time = 0.0
    ResetZ3()
    host = RonoHostTest(1, 1, 1)
    start = time.time()
    res = host.check.CheckIsolationProperty(host.outside, host.host)
    res2 = host.check.CheckIsolationFlowProperty(host.outside, host.host)
    assert res.result == z3.sat and res2.result == z3.unsat
    stop = time.time()
    h_time += (stop - start)
  except:
    h_time = '*'
  print dmz_time, q_time, h_time
