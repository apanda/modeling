import z3
from z3 import is_true, is_false
from examples import *
import time
import mcnet.components
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

print "Running simple erroneous proxy test with firewall (Policy version)"
ResetZ3()
start = time.time()
out = ErroneousProxyMultiFwPi()
result = out.check.CheckIsolationProperty(out.a, out.b)
assert z3.sat == result.result, \
        "No way for packets to get from A -> B but we can't verify that here"
stop = time.time()

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

#print "Without Proxy ACL Firewall"
#start = time.time()
#(eh, check) = withoutProxyAclFw ()
#print check.CheckIsolationProperty(eh[0], eh[2])
#print check.CheckIsolationProperty(eh[1], eh[3])
#print check.CheckIsolationProperty(eh[0], eh[1])
#print check.CheckIsolationProperty(eh[1], eh[2])
#stop = time.time()
#print stop - start
#ResetZ3()

#print "Without Proxy Learning Firewall"
#start = time.time()
#(eh, check) = withoutProxyLearning ()
#print check.CheckIsolationProperty(eh[0], eh[2])
#print check.CheckIsolationProperty(eh[1], eh[3])
#stop = time.time()
#print stop - start
#ResetZ3()

#print "With proxy SAT"
#start = time.time()
#(eh, check) = withProxySat ()
#print check.CheckIsolationProperty(eh[0], eh[2])
#print check.CheckIsolationProperty(eh[1], eh[3])
#stop = time.time()
#print stop - start

#print "With proxy SAT implied"
#start = time.time()
#print check.CheckImpliedIsolation(eh[2], eh[0], eh[0], eh[2])
#stop = time.time()
#print stop - start


#from graph_examples import *
#ResetZ3()
#print "Without proxy ACL firewall (Graph)"
#start = time.time()
#graph = GraphAclFwNoProxy ()
#check = mcnet.components.PropertyChecker(graph.Context, graph.Network)
#print check.CheckIsolationProperty(graph['a'], graph['c'])
#print check.CheckIsolationProperty(graph['b'], graph['d'])
#print check.CheckIsolationProperty(graph['a'], graph['b'])
#print check.CheckIsolationProperty(graph['b'], graph['c'])
#stop = time.time()
#print stop - start

#ResetZ3()
#print "Without proxy Learning firewall (Graph)"
#start = time.time()
#graph = GraphLearnFwNoProxy ()
#check = mcnet.components.PropertyChecker(graph.Context, graph.Network)
#print check.CheckIsolationProperty(graph['a'], graph['c'])
#print check.CheckIsolationProperty(graph['b'], graph['d'])
#print check.CheckIsolationProperty(graph['a'], graph['b'])
#print check.CheckIsolationProperty(graph['b'], graph['c'])
#stop = time.time()
#print stop - start

#REPEAT_ITERS = 1
#ResetZ3()
#print "With proxy 2 learning firewall (Graph)"
#avg = 0
#for iter in xrange(REPEAT_ITERS):
    #start = time.time()
    #graph = GraphLearn2FwProxy ()
    #check = mcnet.components.PropertyChecker(graph.Context, graph.Network)
    #res0 = check.CheckIsolationProperty(graph['a'], graph['c'])
    #res1 = check.CheckIsolationProperty(graph['b'], graph['d'])
    #res2 = check.CheckIsolationProperty(graph['a'], graph['b'])
    #res3 = check.CheckIsolationProperty(graph['b'], graph['c'])
    #stop = time.time()
    #print "This iter %f"%(stop - start)
    #avg += stop - start
    #ResetZ3()
#print res0
#print res1
#print res2
#print res3
#print avg / REPEAT_ITERS


#ResetZ3()
#print "With proxy 1 learning firewall (Graph)"
#avg = 0
#for iter in xrange(REPEAT_ITERS):
    #start = time.time()
    #graph = GraphLearnFwProxy ()
    #check = mcnet.components.PropertyChecker(graph.Context, graph.Network)
    #res0 = check.CheckIsolationProperty(graph['a'], graph['c'])
    #res1 = check.CheckIsolationProperty(graph['b'], graph['d'])
    #res2 = check.CheckIsolationProperty(graph['a'], graph['b'])
    #res3 = check.CheckIsolationProperty(graph['b'], graph['c'])
    #stop = time.time()
    #print "This iter %f"%(stop - start)
    #avg += stop - start
    #ResetZ3()
#print res0
#print res1
#print res2
#print res3
#print avg / REPEAT_ITERS

