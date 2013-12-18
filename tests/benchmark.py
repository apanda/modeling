import z3
from examples import *
import time
import mcnet.components
def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
print "Running timing tests"
print "Two Learning Firewalls"
start = time.time()
(eh, check) = TwoLearningFw()
print check.CheckIsolationProperty(eh[0], eh[2])
print check.CheckIsolationProperty(eh[1], eh[3])
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

ResetZ3()
print "Intrusion Prevention System (UNSAT)"
start = time.time()
d = dpiFw()
chk = d['check']
pred = d['policy'].packetDPIPredicate(d['ctx'])
print chk.CheckIsolatedIf(pred, d['endhosts'][0], d['endhosts'][1])
print chk.CheckIsolatedIf(pred, d['endhosts'][0], d['endhosts'][2])
print chk.CheckIsolatedIf(pred, d['endhosts'][0], d['endhosts'][3])
print chk.CheckIsolatedIf(pred, d['endhosts'][1], d['endhosts'][2])
print chk.CheckIsolatedIf(pred, d['endhosts'][1], d['endhosts'][3])
print chk.CheckIsolatedIf(pred, d['endhosts'][2], d['endhosts'][3])
stop = time.time()
print stop - start

ResetZ3()
print "Intrusion Prevention System with compression SAT"
start = time.time()
d = dpiCompress()
chk = d['check']
pred = d['policy'].packetDPIPredicate(d['ctx'])
print chk.CheckIsolatedIf(pred, d['endhosts'][0], d['endhosts'][1])
print chk.CheckIsolatedIf(pred, d['endhosts'][0], d['endhosts'][2])
print chk.CheckIsolatedIf(pred, d['endhosts'][0], d['endhosts'][3])
print chk.CheckIsolatedIf(pred, d['endhosts'][1], d['endhosts'][2])
print chk.CheckIsolatedIf(pred, d['endhosts'][1], d['endhosts'][3])
print chk.CheckIsolatedIf(pred, d['endhosts'][2], d['endhosts'][3])
stop = time.time()
print stop - start

ResetZ3()
print "Intrusion Prevention System with compression (without decomp) SAT"
start = time.time()
d = dpiCompress2()
chk = d['check']
primitive = d['policy'].packetDPIPredicate(d['ctx'])
decompress = d['gzip'].packetDecompressionPredicate(d['ctx'])
pred = lambda p: (primitive(p) or primitive(decompress(p)))
pred = primitive
print chk.CheckIsolatedIf(pred, d['endhosts'][0], d['endhosts'][1])
print chk.CheckIsolatedIf(pred, d['endhosts'][0], d['endhosts'][2])
print chk.CheckIsolatedIf(pred, d['endhosts'][0], d['endhosts'][3])
print chk.CheckIsolatedIf(pred, d['endhosts'][1], d['endhosts'][2])
print chk.CheckIsolatedIf(pred, d['endhosts'][1], d['endhosts'][3])
print chk.CheckIsolatedIf(pred, d['endhosts'][2], d['endhosts'][3])
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

ResetZ3()
from mcnet.components import DPIPolicy
print "Without proxy DPI firewall (Graph)"
start = time.time()
dpi_policy = DPIPolicy('graph_check')
graph = GraphDpiFwNoProxy (dpi_policy)
check = mcnet.components.PropertyChecker(graph.Context, graph.Network)
pred = dpi_policy.packetDPIPredicate(graph.Context)
print check.CheckIsolatedIf(pred, graph['a'], graph['c'])
print check.CheckIsolatedIf(pred, graph['b'], graph['d'])
print check.CheckIsolatedIf(pred, graph['a'], graph['b'])
print check.CheckIsolatedIf(pred, graph['b'], graph['c'])
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
print res0
print res1
print res2
print res3
print avg / REPEAT_ITERS

