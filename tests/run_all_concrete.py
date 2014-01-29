from concrete_examples import dpiFw, LSRRFwTriv, L7FirewallProxy, L7FirewallProxyPolicy, ReseedZ3, LSRRFwBroken 
from mcnet.components import CheckIsPathIndependentIsolated
import numpy as np
import sys
import time
import z3
def TestDPIFw(iters, raw_data):
    times = []
    print >>raw_data, "TestDPIFw"
    for i in xrange(iters):
        ReseedZ3()
        pobj = dpiFw()
        start = time.time()
        ret = pobj.check.CheckIsolatedIf(pobj.dpi_policy.packetDPIPredicate(pobj.ctx), pobj.a, pobj.b)
        stop = time.time()
        assert ret.result == z3.sat
        times.append(stop - start)
        print >>raw_data, (stop - start)
    print >>raw_data, ""
    print >>raw_data, ""
    print "DPIFw %d %f %f %f %f"%(len(times), sum(times), sum(times)/len(times), np.std(times), np.median(times))

def TestLSRRFwBig(iters, raw_data):
    times = []
    print >>raw_data, "TestLSRRFwBig"
    for i in xrange(iters):
        ReseedZ3()
        pobj = LSRRFwTriv(4)
        start = time.time()
        ret = pobj.check.CheckIsolationProperty(pobj.e0, pobj.e1)
        stop = time.time()
        assert ret.result == z3.sat
        times.append(stop - start)
        print >>raw_data, (stop - start)
    print >>raw_data, ""
    print >>raw_data, ""
    print "LSRRFwBig %d %f %f %f %f"%(len(times), sum(times), sum(times)/len(times), np.std(times), np.median(times))

def TestLSRRFwBigFail(iters, raw_data):
    times = []
    print >>raw_data, "TestLSRRFwBigFail"
    for i in xrange(iters):
        ReseedZ3()
        pobj = LSRRFwBroken(4)
        start = time.time()
        ret = pobj.check.CheckIsolationProperty(pobj.e0, pobj.e1)
        stop = time.time()
        assert ret.result == z3.sat
        times.append(stop - start)
        print >>raw_data, (stop - start)
    print >>raw_data, ""
    print >>raw_data, ""
    print "LSRRFwBigFail %d %f %f %f %f"%(len(times), sum(times), sum(times)/len(times), np.std(times), np.median(times))

def TestLSRRFwNormal(iters, raw_data):
    times = []
    print >>raw_data, "TestLSRRFwNorm"
    for i in xrange(iters):
        ReseedZ3()
        pobj = LSRRFwTriv(2)
        start = time.time()
        ret = pobj.check.CheckIsolationProperty(pobj.e0, pobj.e1)
        stop = time.time()
        assert ret.result == z3.sat
        times.append(stop - start)
        print >>raw_data, (stop - start)
    print >>raw_data, ""
    print >>raw_data, ""
    print "LSRRFwNorm %d %f %f %f %f"%(len(times), sum(times), sum(times)/len(times), np.std(times), np.median(times))

def TestL7FirewallPathIndependence(iters, raw_data):
    times = []
    print >>raw_data, "TestL7FirewallPathIndependence"
    for i in xrange(iters):
        ReseedZ3()
        full_obj = L7FirewallProxy()
        path_obj = L7FirewallProxyPolicy()
        start = time.time()
        ret = CheckIsPathIndependentIsolated(path_obj.check, full_obj.check, path_obj.c, path_obj.a, full_obj.c, full_obj.a, [path_obj.a, path_obj.c, path_obj.p, path_obj.f])
        stop = time.time()
        assert ret.judgement == 2
        times.append(stop - start)
        print >>raw_data, (stop - start)
    print >>raw_data, ""
    print >>raw_data, ""
    print "L7FWPathIndep %d %f %f %f %f"%(len(times), sum(times), sum(times)/len(times), np.std(times), np.median(times))

def TestL7FirewallJustRun (iters, raw_data):
    times = []
    print >>raw_data, "TestL7FirewallJustRun"
    for i in xrange(iters):
        ReseedZ3()
        full_obj = L7FirewallProxy()
        start = time.time()
        ret = full_obj.check.CheckIsolationProperty(full_obj.c, full_obj.a)
        stop = time.time()
        assert ret.result == z3.sat
        times.append(stop - start)
        print >>raw_data, (stop - start)
    print >>raw_data, ""
    print >>raw_data, ""
    print "L7FWPathIndep %d %f %f %f %f"%(len(times), sum(times), sum(times)/len(times), np.std(times), np.median(times))
    print "L7FWPathJR %d %f %f %f %f"%(len(times), sum(times), sum(times)/len(times), np.std(times), np.median(times))
funcs = {'dpifw': TestDPIFw, 'fwnorm':TestLSRRFwNormal, 'l7fwpi':TestL7FirewallPathIndependence, 'l7fwjr':TestL7FirewallJustRun}
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print >>sys.stderr, "Usage: %s iters raw_data"%(sys.argv[0])
        sys.exit(1)
    iters = int(sys.argv[1])
    raw_data = open(sys.argv[2], 'w+')
    for n, f in funcs.iteritems():
        print >>sys.stderr, "Running %s"%(n)
        f(iters, raw_data)
    
