from examples import PFWMultiTenantUnattach
import z3
import time
import random
import sys
import argparse

def ResetZ3 (seed):
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', seed)

def NonRono(tenants, internal, external, samples):
    topo = PFWMultiTenantUnattach(tenants, external, internal)
    topo.net.Attach(*topo.hosts)
    topo.net.Attach(*topo.firewalls)
    # Check all internal unreachable from each other
    total_per_tenant = internal + external
    int_checks = 0
    int_time = 0.0
    for i in xrange(internal):
        if int_checks >= samples:
            break
        for t in xrange(1, tenants):
            start = time.time()
            result = topo.checker.CheckIsolationFlowProperty(topo.hosts[i], topo.hosts[i + (t * total_per_tenant)])
            assert result.result == z3.unsat
            stop = time.time()
            int_time += (stop - start)
            int_checks += 1
            if int_checks >= samples:
                break
    int_average = int_time / float(int_checks)
    # Check externals from other tenants cannot reach internal 0
    ext_int_time = 0.0
    ext_int_checks = 0
    for i in xrange(external):
        if ext_int_checks >= samples:
            break
        for t in xrange(1, tenants):
            start = time.time()
            result = topo.checker.CheckIsolationFlowProperty(topo.hosts[i + (t * total_per_tenant) + internal],\
                    topo.hosts[0])
            assert result.result == z3.unsat
            stop = time.time()
            ext_int_time += (stop - start)
            ext_int_checks += 1
            if ext_int_checks >= samples:
                break

    ext_int_average = ext_int_time / float(ext_int_checks)
    int_ext_checks = 0
    int_ext_time = 0.0
    # Check externals from other tenants are reachable from internal 0
    for i in xrange(external):
        if int_ext_checks >= samples:
            break
        for t in xrange(1, tenants):
            start = time.time()
            result = topo.checker.CheckIsolationFlowProperty(topo.hosts[0],\
                    topo.hosts[i + (t * total_per_tenant) + internal])
            assert result.result == z3.sat
            stop = time.time()
            int_ext_time += (stop - start)
            int_ext_checks += 1
            if int_ext_checks >= samples:
                break
    int_ext_average = int_ext_time / float(int_ext_checks)
    return (int_average, ext_int_average, int_ext_average)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'Non-rono fat-tree test')
    parser.add_argument('--iters', type=int, nargs='?', default=10)
    parser.add_argument('--imin', type=int, nargs='?', default=1)
    parser.add_argument('--imax', type=int, nargs='?', default=10)
    parser.add_argument('--emin', type=int, nargs='?', default=1)
    parser.add_argument('--emax', type=int, nargs='?', default=10)
    parser.add_argument('--tmin', type=int, nargs='?', default=2)
    parser.add_argument('--tmax', type=int, nargs='?', default=25)
    parser.add_argument('--seed', type=int, nargs='?', default=42)
    parser.add_argument('--samples', type=int, nargs='?', default=5)
    args = parser.parse_args()
    iters = args.iters
    int_min = args.imin
    ext_min = args.emin
    tenant_min = args.tmin
    int_max = args.imax
    ext_max = args.emax
    tenant_max = args.tmax
    seed = args.seed
    samples = args.samples
    print "tenant int ext ia eia iea"
    for iter in xrange(iters):
        for tenant in xrange(tenant_min, tenant_max):
            for i in xrange(int_min, int_max):
                for e in xrange(ext_min, ext_max):
                    ResetZ3(seed)
                    (ia, eia, iea) = NonRono(tenant, i, e, samples)
                    print "%d %d %d %f %f %f"%(tenant, i, e, ia, eia, iea)
