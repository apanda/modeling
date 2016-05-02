from examples import DropEverythingTest
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
  for i in xrange(iters):
    dmz_time = 0.0
    for i in xrange(1):
      ResetZ3()
      dmz = DropEverythingTest(1, h, 1)
      # def packet_cond(p):
          # t = z3.Int('_%d_pkt_cond_t'%i)
          # t0 = z3.Int('_%d_pkt_cond_t0'%i)
          # return z3.And(z3.Exists([t], dmz.fw.ddos(dmz.ctx.packet.src(p), t)))
      start = time.time()
      res = dmz.check.CheckIsolationFlowProperty(dmz.outside, dmz.dmz)
      assert res.result == z3.sat
      stop = time.time()
      dmz_time += (stop - start)

    print "%d %f"%(h, dmz_time)
      
