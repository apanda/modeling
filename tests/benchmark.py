import z3
from examples import *
import time
import mcnet.components
def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()

ResetZ3 ()
print "Running simple trivial test"
start = time.time()
out = Trivial()
assert (z3.sat == out.check.CheckIsolationProperty(out.a, out.b)) 
stop = time.time()
print stop - start
ResetZ3 ()

print "Running timing tests"
print "Two Learning Firewalls"
start = time.time()
(eh, check) = TwoLearningFw()
print check.CheckIsolationProperty(eh[0], eh[2])
print check.CheckIsolationProperty(eh[1], eh[3])
print check.CheckIsolationProperty(eh[0], eh[1])
print check.CheckIsolationProperty(eh[2], eh[3])
stop = time.time()
print stop - start
ResetZ3()

print "Without Proxy ACL Firewall"
start = time.time()
(eh, check) = withoutProxyAclFw ()
print check.CheckIsolationProperty(eh[0], eh[2])
print check.CheckIsolationProperty(eh[1], eh[3])
print check.CheckIsolationProperty(eh[0], eh[1])
print check.CheckIsolationProperty(eh[1], eh[2])
stop = time.time()
print stop - start
ResetZ3()

print "Without Proxy Learning Firewall"
start = time.time()
(eh, check) = withoutProxyLearning ()
print check.CheckIsolationProperty(eh[0], eh[2])
print check.CheckIsolationProperty(eh[1], eh[3])
stop = time.time()
print stop - start
ResetZ3()

print "With proxy SAT"
start = time.time()
(eh, check) = withProxySat ()
print check.CheckIsolationProperty(eh[0], eh[2])
print check.CheckIsolationProperty(eh[1], eh[3])
stop = time.time()
print stop - start

print "With proxy SAT implied"
start = time.time()
print check.CheckImpliedIsolation(eh[2], eh[0], eh[0], eh[2])
stop = time.time()
print stop - start

from policy_test import *
ResetZ3()
print "Policy Test SAT"
start = time.time()
TrivialPolicyTest ('A', 'B') 
stop = time.time()
print stop - start

from graph_examples import *
ResetZ3()
print "Without proxy ACL firewall (Graph)"
start = time.time()
graph = GraphAclFwNoProxy ()
check = mcnet.components.PropertyChecker(graph.Context, graph.Network)
print check.CheckIsolationProperty(graph['a'], graph['c'])
print check.CheckIsolationProperty(graph['b'], graph['d'])
print check.CheckIsolationProperty(graph['a'], graph['b'])
print check.CheckIsolationProperty(graph['b'], graph['c'])
stop = time.time()
print stop - start

ResetZ3()
print "Without proxy Learning firewall (Graph)"
start = time.time()
graph = GraphLearnFwNoProxy ()
check = mcnet.components.PropertyChecker(graph.Context, graph.Network)
print check.CheckIsolationProperty(graph['a'], graph['c'])
print check.CheckIsolationProperty(graph['b'], graph['d'])
print check.CheckIsolationProperty(graph['a'], graph['b'])
print check.CheckIsolationProperty(graph['b'], graph['c'])
stop = time.time()
print stop - start

REPEAT_ITERS = 1
ResetZ3()
print "With proxy 2 learning firewall (Graph)"
avg = 0
for iter in xrange(REPEAT_ITERS):
    start = time.time()
    graph = GraphLearn2FwProxy ()
    check = mcnet.components.PropertyChecker(graph.Context, graph.Network)
    res0 = check.CheckIsolationProperty(graph['a'], graph['c'])
    res1 = check.CheckIsolationProperty(graph['b'], graph['d'])
    res2 = check.CheckIsolationProperty(graph['a'], graph['b'])
    res3 = check.CheckIsolationProperty(graph['b'], graph['c'])
    stop = time.time()
    print "This iter %f"%(stop - start)
    avg += stop - start
    ResetZ3()
print res0
print res1
print res2
print res3
print avg / REPEAT_ITERS


ResetZ3()
print "With proxy 1 learning firewall (Graph)"
avg = 0
for iter in xrange(REPEAT_ITERS):
    start = time.time()
    graph = GraphLearnFwProxy ()
    check = mcnet.components.PropertyChecker(graph.Context, graph.Network)
    res0 = check.CheckIsolationProperty(graph['a'], graph['c'])
    res1 = check.CheckIsolationProperty(graph['b'], graph['d'])
    res2 = check.CheckIsolationProperty(graph['a'], graph['b'])
    res3 = check.CheckIsolationProperty(graph['b'], graph['c'])
    stop = time.time()
    print "This iter %f"%(stop - start)
    avg += stop - start
    ResetZ3()
print res0
print res1
print res2
print res3
print avg / REPEAT_ITERS

