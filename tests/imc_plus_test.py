from examples import IMCPlus
import z3
import time
import random
import sys

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))


iters = 2
slice_size = 100
# print "missing_rule_time", "misconfigured_redundancy_time", "correct_time", "traverse_time", "bad_traverse_time"
print "slice_size", "violation_time", "no_violation_time"
for i in xrange(iters):
    for sl in xrange(2, slice_size):
        ResetZ3()
        topo = IMCPlus(sl) # As many nodes as policy classes, saddly.
        s0_addr = topo.addresses[str(topo.servers[0])]
        cc_addr = topo.addresses[str(topo.ccs[0])]
        acls = []
        # [(s0_addr, s1_addr), (s1_addr, s0_addr), (s1_addr, cc_addr), (cc_addr, s1_addr)]
        for s in topo.servers[1:]:
            s_addr = topo.addresses[str(s)]
            acls += [(s0_addr, s_addr), (s_addr, s0_addr), (s_addr, cc_addr), (cc_addr, s_addr)]
        # Step 1 check when no ACLs are being enforced
        try:
            start = time.time()
            ret = topo.check.CheckDataIsolationProperty(topo.servers[0], topo.servers[1])
            assert ret.result == z3.sat
            stop = time.time()
            violation_time = stop-start
        except:
            violation_time = "*"

        topo.fws_out[0].AddAcls(acls)
        topo.fws_out[1].AddAcls(acls)   

        # Step 2 check when ACLs are being enforced
        try:
            start = time.time()
            ret = topo.check.CheckDataIsolationProperty(topo.servers[0], topo.servers[1])
            assert ret.result == z3.unsat
            stop = time.time()
            no_violation_time = stop-start
        except:
            no_violation_time = "*"
        print sl, violation_time, no_violation_time
