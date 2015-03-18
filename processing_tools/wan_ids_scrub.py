import sys
from collections import defaultdict

def Process (fnames):
    times = defaultdict(lambda: 0.0)
    count = defaultdict(lambda: 0)
    for fname in fnames:
        f = open(fname)
        for l in f:
            if l.startswith("internal") or l.startswith("external"):
                continue
            parts = l.strip().split()
            internal = int(parts[0])
            external = int(parts[1])
            time = float(parts[2])
            
            num_checks = external * internal
            times[(internal, external)] += float(num_checks) * time
            count[(internal, external)] += 1
    print "# int ext time"
    for k in sorted(count.keys()):
        (i, e) = k
        print "%d %d %f"%(i, e, times[k] / float(count[k]))

if __name__ == "__main__":
    Process(sys.argv[1:])

