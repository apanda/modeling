from examples import *
import time
print "Running timing tests"
print "Two Learning Firewalls"
start = time.time()
(eh, check) = TwoLearningFw()
print check.CheckIsolationProperty(eh[0], eh[2])
print check.CheckIsolationProperty(eh[1], eh[3])
stop = time.time()
print stop - start


print "Without Proxy ACL Firewall"
start = time.time()
(eh, check) = withoutProxyAclFw ()
print check.CheckIsolationProperty(eh[0], eh[2])
print check.CheckIsolationProperty(eh[1], eh[3])
stop = time.time()
print stop - start

print "Without Proxy Learning Firewall"
start = time.time()
(eh, check) = withoutProxyLearning ()
print check.CheckIsolationProperty(eh[0], eh[2])
print check.CheckIsolationProperty(eh[1], eh[3])
stop = time.time()
print stop - start

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
print stop - start()
