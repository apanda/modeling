import sys
import numpy as np
if len(sys.argv) != 2:
    print >>sys.stderr, "Usage: %s file"%(sys.argv[0])
f = open(sys.argv[1])
for l in f:
    parts = l.split()[:-1]
    num = int(parts[0])
    obs = map(float, parts[1:])
    if len(obs) == 0:
        continue
    median = np.median(obs)
    #if len(obs) > 4:
        #obs = filter(lambda o: o < 10.0 * median, obs)
    s = sum(obs)
    avg = s/float(len(obs))
    print "%s %f %f %d %f %f %f %f"%(num, avg, s, len(obs), np.std(obs), np.median(obs), min(obs), max(obs))
