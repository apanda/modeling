import sys
from collections import defaultdict

def Process (fnames):
    tenant_time = defaultdict(lambda: defaultdict(lambda: 0.0))
    tenant_run = defaultdict(lambda: defaultdict(lambda:0))
    for fname in fnames:
        f = open(fname)
        for l in f:
            if l.startswith("tenant"):
                continue
            parts = l.strip().split()
            tenants = int(parts[0])
            priv = int(parts[1])
            pub = int(parts[2])
            num_machines = tenants * priv * pub
            
            int_checks = (tenants * tenants * priv * (priv - 1)) / 2
            int_time = int_checks * float(parts[3]) 

            ext_checks = (tenants * priv) * ((tenants - 1) * pub)
            ext_time = ext_checks * float(parts[4])

            oext_check = (tenants * priv) * (tenants * pub)
            oext_time = oext_check * float(parts[5])
            total = int_time + ext_time + oext_time
            tenant_time[(priv, pub)][tenants] += total
            tenant_run[(priv, pub)][tenants] += 1

    for k in sorted(tenant_run.keys()):
        print "# ----%s------"%(str(k))
        for k2 in sorted(tenant_run[k].keys()):
            print "%d %d %f"%(k2, tenant_run[k][k2], \
                    tenant_time[k][k2]/float(tenant_run[k][k2]))
        print
        print
        #print "%d %d %f"%(k, runs[k], machines[k]/float(runs[k]))

if __name__ == "__main__":
    Process(sys.argv[1:])
