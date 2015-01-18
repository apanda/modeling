from examples import FlatTenant, RichMultiTenant, FlatTenantUnattach, RichMultiTenantUnattach
import z3
import time
import random
import sys

def ResetZ3 ():
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', random.SystemRandom().randint(0, sys.maxint))

def NonRono(tenants, internal, external):
    # Check all internal unreachable from each other
    total_per_tenant = internal + external
    int_checks = 0
    int_time = 0.0
    for i in xrange(internal):
        for t in xrange(1, tenants):
            ResetZ3()
            topo = RichMultiTenantUnattach(tenants, external, internal)
            start = time.time()
            topo.net.Attach(topo.hosts[i], topo.hosts[i + (t * total_per_tenant)], \
                          topo.firewalls[i], topo.firewalls[i + (t * total_per_tenant)])
            result = topo.checker.CheckIsolationFlowProperty(topo.hosts[i], topo.hosts[i + (t * total_per_tenant)])
            assert result.result == z3.unsat
            stop = time.time()
            int_time += (stop - start)
            int_checks += 1
    int_average = int_time / float(int_checks)
    # Check externals from other tenants cannot reach internal 0
    ext_int_time = 0.0
    ext_int_checks = 0
    for i in xrange(external):
        for t in xrange(1, tenants):
            ResetZ3()
            topo = RichMultiTenantUnattach(tenants, external, internal)
            start = time.time()
            topo.net.Attach(topo.hosts[i + (t * total_per_tenant) + internal],\
                    topo.hosts[0],\
                    topo.firewalls[i + (t * total_per_tenant) + internal],\
                    topo.firewalls[0])
            result = topo.checker.CheckIsolationFlowProperty(topo.hosts[i + (t * total_per_tenant) + internal],\
                    topo.hosts[0])
            assert result.result == z3.unsat
            stop = time.time()
            ext_int_time += (stop - start)
            ext_int_checks += 1
    ext_int_average = ext_int_time / float(ext_int_checks)
    int_ext_checks = 0
    int_ext_time = 0.0
    # Check externals from other tenants are reachable from internal 0
    for i in xrange(external):
        for t in xrange(1, tenants):
            ResetZ3()
            topo = RichMultiTenantUnattach(tenants, external, internal)
            start = time.time()
            topo.net.Attach(topo.hosts[0],\
                    topo.hosts[i + (t * total_per_tenant) + internal],\
                    topo.firewalls[0],\
                    topo.firewalls[i + (t * total_per_tenant) + internal])
            result = topo.checker.CheckIsolationFlowProperty(topo.hosts[0],\
                    topo.hosts[i + (t * total_per_tenant) + internal])
            assert result.result == z3.sat
            stop = time.time()
            int_ext_time += (stop - start)
            int_ext_checks += 1
    int_ext_average = int_ext_time / float(int_ext_checks)
    return (int_average, ext_int_average, int_ext_average)

if __name__ == "__main__":
    iters = 10
    int_min = 1
    ext_min = 1
    tenant_min = 2
    int_max = 10
    ext_max = 10
    tenant_max = 25
    print "tenant int ext ia eia iea"
    for iter in xrange(iters):
        for tenant in xrange(tenant_min, tenant_max):
            for i in xrange(int_min, int_max):
                for e in xrange(ext_min, ext_max):
                    (ia, eia, iea) = NonRono(tenant, i, e)
                    print "%d %d %d %f %f %f"%(tenant, i, e, ia, eia, iea)
