import sys
from collections import defaultdict

def Process (fnames):
    times = defaultdict(lambda: 0.0)
    count = defaultdict(lambda: 0)
    time_min = defaultdict(lambda: float("inf"))
    time_max = defaultdict(lambda: 0.0)
    for fname in fnames:
        f = open(fname)
        for l in f:
            if l.startswith("internal") or l.startswith("external"):
                continue
            parts = l.strip().split()
            internal = int(parts[0])
            external = int(parts[1])
            time = float(parts[2])
            
            times[(internal, external)] +=  time
            count[(internal, external)] += 1
            time_min[(internal, external)] = min(time_min[(internal, external)], time)
            time_max[(internal, external)] = min(time_max[(internal, external)], time)
    print "# int ext time min max"
    for k in sorted(count.keys()):
        (i, e) = k
        print "%d %d %f %f %f"%(i, e, times[k] / float(count[k]), time_min[k], time_max[k])

if __name__ == "__main__":
    Process(sys.argv[1:])

