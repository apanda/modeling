from examples import IMC, IMCBad
import z3
import time
import random
import sys

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

iters = 10000
print "missing_rule_time", "misconfigured_redundancy_time", "correct_time", "traverse_time", "bad_traverse_time"
for i in xrange(iters):
  ResetZ3()
  topo = IMC(3) # 0 and 1 are nodes, 2 is internet.


  acls = [(topo.addresses[str(topo.servers[0])], topo.addresses[str(topo.servers[1])]), \
          (topo.addresses[str(topo.servers[1])], topo.addresses[str(topo.servers[0])])]

  # Missing rules (assume we want 0 and 1 to be isolated)
  start = time.time()
  ret = topo.check.CheckIsolationProperty(topo.servers[0], topo.servers[1])
  stop = time.time()
  assert ret.result == z3.sat
  missing_rule_time = stop - start

  # Misconfigured redundant firewall
  topo.fws_out[0].AddAcls(acls)
  start = time.time()
  ret = topo.check.CheckIsolationProperty(topo.servers[0], topo.servers[1])
  stop = time.time()
  assert ret.result == z3.sat
  misconfigured_redundancy_time = stop - start

  # No errors
  topo.fws_out[1].AddAcls(acls)
  start = time.time()
  ret = topo.check.CheckIsolationProperty(topo.servers[0], topo.servers[1])
  stop = time.time()
  assert ret.result == z3.unsat
  correct_time = stop - start

  # Check traversal (correct)
  start = time.time()
  ret = topo.check.CheckNodeTraversalProperty(topo.servers[2], topo.servers[1], topo.dpis)
  assert ret.result == z3.unsat
  stop = time.time()
  traverse_time = stop-start

  topo = IMCBad(3)
  start = time.time()
  ret = topo.check.CheckNodeTraversalProperty(topo.servers[2], topo.servers[1], topo.dpis)
  assert ret.result == z3.sat
  stop = time.time()
  bad_traverse_time = stop - start

  print missing_rule_time, misconfigured_redundancy_time, correct_time, traverse_time, bad_traverse_time

