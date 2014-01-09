import z3
from z3 import is_true, is_false
from examples import *
import time
import mcnet.components as components
def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()

print "Running simple trivial test"
ResetZ3 ()
start = time.time()
out = Trivial()
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.sat == result.result, \
        "Trivial Check Failed"
assert is_true(result.model.eval(out.ctx.send(out.a.z3Node, out.b.z3Node, result.violating_packet))), \
        "Whoa the packet was never sent"
stop = time.time()
print stop - start

print "Running timing tests"
print "Two Learning Firewalls"
ResetZ3 ()
start = time.time()
(eh, check) = TwoLearningFw()
c1 = check.CheckIsolationProperty(eh[0], eh[2])
assert z3.unsat == c1.result, \
        "Should be unsat; the firewall drops all packets from A -> C"
print c1.result
c2 = check.CheckIsolationProperty(eh[1], eh[3])
assert z3.unsat == c2.result,\
        "Should be unsat; firewall drops all packets from B -> D"
print c2.result
c3 = check.CheckIsolationProperty(eh[0], eh[1])
assert z3.sat == c3.result, \
        "Should be SAT; firewall allows packet from A -> B"
print c3.result
c4 = check.CheckIsolationProperty(eh[2], eh[3])
assert z3.sat == c4.result, \
        "Should be SAT; firewall allows packets from B -> C"
print c4.result
stop = time.time()
print stop - start

print "Running simple compression test"
ResetZ3()
start = time.time()
out = TrivialWanOptimizer()
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.sat == result.result, \
        "Nothing is blocking the way, packets should get from A -> B"
assert is_true(result.model.eval(out.ctx.send(out.w.z3Node, out.b.z3Node, result.violating_packet))), \
        "Violating packet was never sent"
assert is_true(result.model.eval(out.ctx.recv(out.w.z3Node, out.b.z3Node, result.violating_packet))), \
        "Violating packet was never received"
assert is_false(result.model.eval(out.ctx.recv(out.a.z3Node, out.w.z3Node, result.violating_packet))), \
        "The packet should not get to b unmodified"
assert is_false(result.model.eval(out.ctx.send(out.a.z3Node, out.w.z3Node, result.violating_packet))), \
        "The packet should not get to b unmodified"
stop = time.time()
print stop - start

print "Running simple compression-decompression test"
ResetZ3()
start = time.time()
out = TrivialWanOptimizerDeOptimizer()
result = out.check.CheckIsolatedIf(lambda p: z3.Not(out.ctx.send(out.w0.z3Node, out.w1.z3Node, p)), out.a, out.b)
assert z3.sat == result.result, \
        "Nothing is blocking the way, packets should get from A -> B"
assert is_true(result.model.eval(out.ctx.send(out.w1.z3Node, out.b.z3Node, result.violating_packet))), \
        "Violating packet was never sent"
assert is_true(result.model.eval(out.ctx.recv(out.w1.z3Node, out.b.z3Node, result.violating_packet))), \
        "Violating packet was never received"
assert is_true(result.model.eval(out.ctx.recv(out.a.z3Node, out.w0.z3Node, result.violating_packet))), \
        "The packet that gets to b was sent by a"
assert is_false(result.model.eval(out.ctx.send(out.w0.z3Node, out.w1.z3Node, result.violating_packet))), \
        "The original packet never goes through the network"
stop = time.time()
print stop - start

print "Running simple compression-DPI-decompression test"
ResetZ3()
start = time.time()
out = TrivialWanOptimizerAndDPI()
result = out.check.CheckIsolatedIf(out.dpi_policy.packetDPIPredicate(out.ctx), out.a, out.b)
assert z3.sat == result.result, \
        "Nothing is blocking the way, packets should get from A -> B"
assert is_true(result.model.eval(out.ctx.send(out.w1.z3Node, out.b.z3Node, result.violating_packet))), \
        "Violating packet was never sent"
assert is_true(result.model.eval(out.ctx.recv(out.w1.z3Node, out.b.z3Node, result.violating_packet))), \
        "Violating packet was never received"
assert is_true(result.model.eval(out.ctx.recv(out.a.z3Node, out.w0.z3Node, result.violating_packet))), \
        "The packet that gets to b was sent by a"
assert is_false(result.model.eval(out.ctx.send(out.w0.z3Node, out.d.z3Node, result.violating_packet))), \
        "The original packet never goes through the network"
assert is_false(result.model.eval(out.ctx.send(out.d.z3Node, out.w1.z3Node, result.violating_packet))), \
        "The original packet never goes through the network"
assert is_true(result.model.eval(out.dpi_policy.packetDPIPredicate(out.ctx)(result.violating_packet))), \
        "The packet violates DPI"
stop = time.time()
print stop - start

print "Running simple proxy test"
ResetZ3()
start = time.time()
out = TrivialProxy()
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.sat == result.result, \
        "Nothing is blocking the way, packets should get from A -> B"
assert is_true(result.model.eval(out.ctx.send(out.p.z3Node, out.b.z3Node, result.violating_packet))), \
        "Violating packet was never sent"
assert is_true(result.model.eval(out.ctx.recv(out.p.z3Node, out.b.z3Node, result.violating_packet))), \
        "Violating packet was never received"
assert is_false(result.model.eval(out.ctx.recv(out.a.z3Node, out.p.z3Node, result.violating_packet))), \
        "The packet that gets to b was sent by a (instead of the proxy)"
stop = time.time()
print stop - start

print "Running simple erroneous proxy test"
ResetZ3()
start = time.time()
out = ErroneousProxy()
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.unsat == result.result, \
        "No way for packets to get from A -> B"
stop = time.time()
print stop - start

print "Running simple erroneous proxy test with multiple players"
ResetZ3()
start = time.time()
out = ErroneousProxyMultiple()
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.sat == result.result, \
        "The presence of C implies packets can get through"
assert z3.is_true(result.model.eval(out.ctx.packet.src(result.violating_packet) == out.ctx.ip_p)), \
        "The violating packet must have started at the proxy, no direct path"
cached = result.model[result.model[out.p.cached].else_value().decl()].as_list()
assert len(cached) == 2, \
        "This is not a failure per-se, manually inspect model to see what is going on"

assert z3.is_true(result.model.eval(out.ctx.packet.body(result.violating_packet) == \
                                        out.p.cresp(cached[0][0], cached[0][1]))), \
        "Response should be a cached response"

assert z3.is_true(result.model.eval(out.p.ctime(cached[0][0], cached[0][1]) < \
                    out.ctx.etime(out.p.z3Node, result.violating_packet, out.ctx.send_event))), \
        "Cannot send a cached response before it is actually cached"

assert z3.is_true(result.model.eval(out.ctx.etime(out.p.z3Node, out.p.crespacket(cached[0][0], cached[0][1]), out.ctx.recv_event) < \
                                    out.ctx.etime(out.p.z3Node, result.violating_packet, out.ctx.send_event)))
stop = time.time()
print stop - start

print "Running simple erroneous proxy test with firewall"
ResetZ3()
start = time.time()
out = ErroneousProxyMultiFw()
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.unsat == result.result, \
        "No way for packets to get from A -> B"
stop = time.time()
print stop - start

print "Running ACL proxy test with multiple player"
ResetZ3()
start = time.time()
out = AclProxyMultiple()
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.unsat == result.result, \
        "No way for packets to get from A -> B"
stop = time.time()
print stop - start

print "Running simple LoadBalancer test"
ResetZ3()
start = time.time()
out = TrivialLbalancer()
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.sat == result.result, \
        "One path for packets to get from A -> B"
assert z3.is_true(result.model.eval(result.ctx.send(out.a.z3Node, out.l.z3Node, result.violating_packet))), \
        "Path goes through L"
assert z3.is_true(result.model.eval(result.ctx.send(out.l.z3Node, out.b.z3Node, result.violating_packet))), \
        "Path goes through L"
stop = time.time()
print stop - start

print "Running more complex LoadBalancer test"
ResetZ3()
start = time.time()
out = TrivialLbalancer()
p0 = z3.Const('complex_packet', out.ctx.packet)
predicate = z3.And(out.ctx.send(out.l.z3Node, out.f.z3Node, p0), \
                    out.ctx.packet.src(p0) == out.ctx.ip_a)
out.check.AddExternalConstraints (predicate)
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.sat == result.result, \
        "One path for packets to get from A -> B"
assert z3.is_true(result.model.eval(result.ctx.send(out.a.z3Node, out.l.z3Node, result.violating_packet))), \
        "Path goes through L"
assert z3.is_true(result.model.eval(result.ctx.send(out.l.z3Node, out.b.z3Node, result.violating_packet))), \
        "Path goes through L"
assert z3.is_true(result.model.eval(result.ctx.send(out.l.z3Node, out.f.z3Node, p0))), \
        "We required a packet to go through the firewall"
assert z3.is_true(result.model.eval(result.ctx.etime(out.b.z3Node, p0, result.ctx.recv_event) == 0)), \
        "We required a packet to go through the firewall, the firewall should drop it"
p1 = result.violating_packet
assert z3.is_false(result.model.eval(out.l.hash_function(result.ctx.src_port(p0), result.ctx.dest_port(p0)) == \
                        out.l.hash_function(result.ctx.src_port(p1), result.ctx.dest_port(p1))))
stop = time.time()
print stop - start

print "Running LoadBalancer traversal check"
ResetZ3()
start = time.time()
out = TrivialLbalancer()
result = out.check.CheckTraversalProperty(out.a, out.b, out.f)
assert z3.sat == result.result, \
        "There are packets that can go from A to B without going through F"
stop = time.time()
print stop - start

print "Running simple counter example"
ResetZ3()
start = time.time()
out = TrivialCtrExample ()
result = out.check.CheckTraversalProperty(out.a, out.b, out.c)
assert z3.unsat == result.result, \
        "Must go through the counter to get to B"
stop = time.time()
print stop - start

print "Running LoadBalancer traversal check"
ResetZ3()
start = time.time()
out = TrivialLbalancer()
result = out.check.CheckTraversalThroughGroup(out.a, out.b, [out.f])
assert z3.sat == result.result, \
        "There are packets that can go from A to B without going through F"
stop = time.time()
print stop - start

print "Running simple counter example"
ResetZ3()
start = time.time()
out = TrivialCtrExample ()
result = out.check.CheckTraversalThroughGroup(out.a, out.b, [out.c])
assert z3.unsat == result.result, \
        "Must go through the counter to get to B"
stop = time.time()
print stop - start

print "Running LSRR test"
ResetZ3()
start = time.time()
obj = LSRRExample ()
ret = obj.check.CheckIsolatedIf(lambda p: obj.ctx.send(obj.b.z3Node, obj.e1.z3Node, p), obj.e0, obj.e1)
assert z3.sat == ret.result, \
        "Satisfiable, no blocks"
assert z3.is_true(ret.model.eval(ret.ctx.send(obj.b.z3Node, obj.e1.z3Node, ret.violating_packet))), \
        "Need to go through b"
stop = time.time()
print stop - start

for sz in xrange(3, 6):
    print "Running complex LSRR test with size %d"%(sz)
    ResetZ3()
    start = time.time()
    obj = LSRRFwExample (sz)
    ret = obj.check.CheckIsolationProperty(obj.e0, obj.e1)
    assert z3.sat == ret.result, \
            "Satisfiable, no blocks"
    stop = time.time()
    print stop - start

for sz in xrange(2, 5):
    print "Running num node test with size %d"%(sz)
    ResetZ3()
    start = time.time()
    obj = NumFwTest (sz)
    ret = obj.check.CheckIsolationProperty(obj.e_0, obj.e_1)
    assert z3.unsat == ret.result, \
            "No way to go"
    ret = obj.check.CheckIsolationProperty(obj.e_0, obj.e_2)
    assert z3.sat == ret.result, \
            "Nothing stopping this"
    ret = obj.check.CheckIsolationProperty(obj.e_0, obj.e_3)
    assert z3.sat == ret.result, \
            "Nothing stopping this"
    stop = time.time()
    print stop - start

print "Running simple erroneous proxy test with firewall (Policy version)"
ResetZ3()
start = time.time()
out = ErroneousProxyMultiFwPi()
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.sat == result.result, \
        "No way for packets to get from A -> B but we can't verify that here"
stop = time.time()
print stop - start

print "Running ACL proxy test with firewall (Policy version)"
ResetZ3()
start = time.time()
out = AclProxyMultiFwPi()
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.unsat == result.result, \
        "No way for packets to get from A -> B but we can't verify that here"
stop = time.time()
print stop - start

from policy_test import *
ResetZ3()
print "Policy Test SAT"
start = time.time()
res, chk, ctx = TrivialPolicyTest ()
assert res.result == z3.unsat, \
        "No one can produce bad packet in this case"
print res.result
stop = time.time()
print stop - start


print "Running automatic detection of path isolation: Erroneous proxy with firewall"
ResetZ3()
start= time.time()
policy_obj = ErroneousProxyMultiFwPi()
full_obj = ErroneousProxyMultiFw()
result = components.CheckIsPathIndependentIsolated (policy_obj.check, full_obj.check, policy_obj.a, policy_obj.b, full_obj.a, full_obj.b, policy_obj.participants)
assert result.judgement == components.VERIFIED_GLOBAL, \
        "Can't verify this locally"
assert result.result == z3.unsat, \
        "See previous"
stop = time.time()
print stop - start

print "Running automatic detection of path isolation: ACL proxy with firewall"
ResetZ3()
start= time.time()
policy_obj = AclProxyMultiFwPi()
full_obj = AclProxyMultiFw()
result = components.CheckIsPathIndependentIsolated (policy_obj.check, full_obj.check, policy_obj.a, policy_obj.b, full_obj.a, full_obj.b, policy_obj.participants)
assert result.judgement == components.VERIFIED_ISOLATION, \
        "Should verify locally"
assert result.result == z3.unsat, \
        "See previous"
stop = time.time()
print stop - start

print "Running automatic detection of path isolation: Erroneous proxy without firewall"
ResetZ3()
start= time.time()
policy_obj = ErroneousProxyMultiplePi()
full_obj = ErroneousProxyMultiple()
result = components.CheckIsPathIndependentIsolated (policy_obj.check, full_obj.check, policy_obj.a, policy_obj.b, full_obj.a, full_obj.b, policy_obj.participants)
assert result.judgement == components.VERIFIED_GLOBAL, \
        "Can't verify this locally"
assert result.result == z3.sat, \
        "See previous"
stop = time.time()
print stop - start

