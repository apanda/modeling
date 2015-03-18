import sys

def Process (fnames):
    machines = {}
    runs = {}
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
            machines[num_machines] = machines.get(num_machines, 0.0) + total
            runs[num_machines] = runs.get(num_machines, 0.0) + 1
    for k in sorted(runs.keys()):
        print "%d %d %f"%(k, runs[k], machines[k]/float(runs[k]))

if __name__ == "__main__":
    Process(sys.argv[1:])
