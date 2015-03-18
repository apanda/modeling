import sys
from collections import defaultdict

def Process (fnames):
    ttime = defaultdict(lambda: 0.0)
    count = defaultdict(lambda: 0)
    for fname in fnames:
        f = open(fname)
        for l in f:
            if l.startswith("size"):
                continue
            parts = l.strip().split()
            size = int(parts[0])
            time = float(parts[1]) + float(parts[2])
            ttime[size] += time
            count[size] += 1
            #tenant_time[(priv, pub)][tenants] += total
            #tenant_run[(priv, pub)][tenants] += 1

    for k in sorted(ttime.keys()):
         print "%d %f"%(k, ttime[k]/ float(count[k]))
if __name__ == "__main__":
    Process(sys.argv[1:])
